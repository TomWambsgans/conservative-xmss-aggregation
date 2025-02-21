use array_init::array_init;
use binius_circuits::{
    builder::{witness, ConstraintSystemBuilder},
    transparent,
};
use binius_core::oracle::OracleId;
use binius_field::{BinaryField, BinaryField1b, ExtensionField, Field, PackedField, TowerField};
use binius_math::ArithExpr;

use super::n_vars_for;
use crate::{
    arithmetization::channels::Channels,
    config::{W, XMSS_HEIGHT},
    utils::{
        fill_multiple_witness_col, fill_rows, fill_witness_col, B128, B16, B64, B8,
        KECCAK256_PADDING_LEFT, KECCAK256_PADDING_RIGHT, N_WOTS_CHUNKS,
        N_WOTS_PUBKEY_KECCAKF_STATES, VERIFIER_WOTS_HASHES, WOTS_CHAIN_SIZE,
    },
    xmss::XmssVerificationWitness,
};

#[derive(Clone, Debug)]
pub struct ChainHeadTable {
    pub count: usize,
    pub n_vars: usize,
    pub chain_length: [OracleId; N_WOTS_CHUNKS], // each is 2-bytes
    pub chain_length_additive: [OracleId; N_WOTS_CHUNKS], // each is 2-bytes
    pub chain_end: [[OracleId; 4]; N_WOTS_CHUNKS], // each is 8-bytes
    pub intermediate_state: [[OracleId; 25]; N_WOTS_PUBKEY_KECCAKF_STATES], // each is 8-bytes
    pub xored_intermediate_state: [[OracleId; 25]; N_WOTS_PUBKEY_KECCAKF_STATES], // each is 8-bytes - virtual
    pub keccak_truncated_bits: [OracleId; 21],                                    // each is 8-bytes
    pub wots_public_key: [OracleId; 4],                                           // each is 8-bytes
    pub chain_length_additive_packed: [OracleId; 4], // each is 8-bytes - virtual (should be equal to derived_msg_digest)
    pub lookup_read_timestamp: [OracleId; N_WOTS_CHUNKS], // each is 8-bytes
    pub lookup_write_timestamp: [OracleId; N_WOTS_CHUNKS], // each is 8-bytes - virtual
    pub signature_index: OracleId,                   // 2 bytes
}

impl super::Table for ChainHeadTable {
    fn count(&self) -> usize {
        self.count
    }

    fn n_vars(&self) -> usize {
        self.n_vars
    }

    fn build<'arena>(
        builder: &mut ConstraintSystemBuilder<'arena>,
        channels: &Channels,
        aggregation_count: usize,
    ) -> Self {
        builder.push_namespace("chain_");
        let count = aggregation_count;
        let n_vars = n_vars_for::<B16>(count);

        let lookup_read_timestamp =
            builder.add_committed_multiple("lookup_read_timestamp", n_vars, B64::TOWER_LEVEL);
        let mut res = Self {
            count,
            n_vars,
            chain_length: builder.add_committed_multiple("chain_length", n_vars, B16::TOWER_LEVEL),
            chain_length_additive: builder.add_committed_multiple(
                "chain_length_additive",
                n_vars,
                B16::TOWER_LEVEL,
            ),
            chain_end: {
                let mut oracles = [[0; 4]; N_WOTS_CHUNKS];
                for i in 0..N_WOTS_CHUNKS {
                    oracles[i] = builder.add_committed_multiple(
                        format!("chain_end-{i}"),
                        n_vars,
                        B64::TOWER_LEVEL,
                    );
                }
                oracles
            },
            intermediate_state: {
                let mut oracles = [[0; 25]; N_WOTS_PUBKEY_KECCAKF_STATES];
                for i in 0..N_WOTS_PUBKEY_KECCAKF_STATES {
                    oracles[i] = builder.add_committed_multiple(
                        format!("intermediate_state-{i}"),
                        n_vars,
                        B64::TOWER_LEVEL,
                    );
                }
                oracles
            },
            keccak_truncated_bits: builder.add_committed_multiple(
                "keccak_truncated_bits",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            wots_public_key: builder.add_committed_multiple(
                "wots_public_key",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            signature_index: builder.add_committed("signature_index", n_vars, B16::TOWER_LEVEL),
            chain_length_additive_packed: [0; 4],
            lookup_read_timestamp,
            lookup_write_timestamp: {
                let mut oracles = [0; N_WOTS_CHUNKS];
                for i in 0..N_WOTS_CHUNKS {
                    oracles[i] = builder
                        .add_linear_combination(
                            format!("lookup_write_timestamp-{i}"),
                            n_vars,
                            [(
                                lookup_read_timestamp[i],
                                B128::from(B64::MULTIPLICATIVE_GENERATOR),
                            )],
                        )
                        .unwrap();
                }
                oracles
            },
            xored_intermediate_state: [[0; 25]; N_WOTS_PUBKEY_KECCAKF_STATES],
        };

        for col in res.lookup_read_timestamp {
            builder.assert_not_zero(col);
        }

        builder.assert_zero(
            "sumcheck",
            res.chain_length,
            ArithExpr::Const(B128::from(
                B16::MULTIPLICATIVE_GENERATOR.pow(VERIFIER_WOTS_HASHES as u64),
            )) - (0..N_WOTS_CHUNKS).map(|i| ArithExpr::Var(i)).product(),
        );

        for i in 0..N_WOTS_CHUNKS {
            let wots_chunck = binius_circuits::transparent::constant(
                builder,
                &format!("generator_pow_{i}"),
                n_vars,
                B8::from(i as u8),
            )
            .unwrap();
            builder
                .receive(channels.hash_chain_counter, count, {
                    let mut oracle_ids = res.chain_end[i].to_vec();
                    oracle_ids.push(res.signature_index);
                    oracle_ids.push(res.chain_length[i]);
                    oracle_ids.push(wots_chunck);

                    oracle_ids
                })
                .unwrap();
        }

        let generator_pow_h = binius_circuits::transparent::constant(
            builder,
            &format!("generator_pow_{XMSS_HEIGHT}"),
            n_vars,
            B8::MULTIPLICATIVE_GENERATOR.pow(XMSS_HEIGHT as u64),
        )
        .unwrap();

        builder
            .send(channels.merkle, count, {
                let mut oracle_ids = res.wots_public_key.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids.push(generator_pow_h); // xmss_depth

                oracle_ids
            })
            .unwrap();

        for i in 0..4 {
            let sub_oracles =
                &res.chain_length_additive[i * N_WOTS_CHUNKS / 4..(i + 1) * N_WOTS_CHUNKS / 4];
            res.chain_length_additive_packed[i] = builder
                .add_linear_combination(
                    format!("chain_length_additive_packed-{i}"),
                    n_vars,
                    sub_oracles
                        .iter()
                        .enumerate()
                        .map(|(j, oracle_id)| {
                            (
                                *oracle_id,
                                <B128 as ExtensionField<BinaryField1b>>::basis(W * j).unwrap(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap();
        }
        builder
            .send(channels.derived_message_digest, count, {
                let mut oracle_ids = res.chain_length_additive_packed.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids
            })
            .unwrap();

        let mut middle = 17;
        let mut c = 17; // the first 17 * 8 bytes of res.hash are not xored, but directly fed to the keccakf-channel instead
        for i in 0..N_WOTS_PUBKEY_KECCAKF_STATES {
            if i == N_WOTS_PUBKEY_KECCAKF_STATES - 1 {
                middle = (N_WOTS_CHUNKS * 4).checked_sub(c).unwrap();
                assert!(middle < 17);
            }
            for j in 0..middle {
                res.xored_intermediate_state[i][j] = builder
                    .add_linear_combination(
                        format!("xor-{i}-{j}"),
                        n_vars,
                        [
                            (res.intermediate_state[i][j], B128::ONE),
                            (res.chain_end[c / 4][c % 4], B128::ONE),
                        ],
                    )
                    .unwrap();
                c += 1;
            }
            for j in middle..25 {
                res.xored_intermediate_state[i][j] = res.intermediate_state[i][j];
            }
        }

        let keccak_padding_0x01_0x80 = transparent::constant(
            builder,
            "padding-0x01_0x80",
            n_vars,
            B64::from((0x80 << 56) | KECCAK256_PADDING_LEFT),
        )
        .unwrap();
        let keccak_padding_0x01 = transparent::constant(
            builder,
            "padding-0x01",
            n_vars,
            B64::from(KECCAK256_PADDING_LEFT),
        )
        .unwrap();
        let zeros = transparent::constant(builder, "zeros", n_vars, B64::ZERO).unwrap();
        let keccak_padding_0x80 = transparent::constant(
            builder,
            "padding-0x80",
            n_vars,
            B64::from(KECCAK256_PADDING_RIGHT),
        )
        .unwrap();

        assert!(middle < 17);

        // padding
        if middle == 16 {
            res.xored_intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][middle] = builder
                .add_linear_combination(
                    format!("xor-padding-0x01_0x80"),
                    n_vars,
                    [
                        (
                            res.intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][middle],
                            B128::ONE,
                        ),
                        (keccak_padding_0x01_0x80, B128::ONE),
                    ],
                )
                .unwrap();
        } else {
            res.xored_intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][middle] = builder
                .add_linear_combination(
                    format!("xor-padding-0x01"),
                    n_vars,
                    [
                        (
                            res.intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][middle],
                            B128::ONE,
                        ),
                        (keccak_padding_0x01, B128::ONE),
                    ],
                )
                .unwrap();

            res.xored_intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][16] = builder
                .add_linear_combination(
                    format!("xor-padding-0x80"),
                    n_vars,
                    [
                        (
                            res.intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][16],
                            B128::ONE,
                        ),
                        (keccak_padding_0x80, B128::ONE),
                    ],
                )
                .unwrap();
        }

        // first push to the keccakf-channel
        {
            let mut keccak_oracles_id = [0; 50];
            // input
            keccak_oracles_id[0..4].copy_from_slice(&res.chain_end[0]);
            keccak_oracles_id[4..8].copy_from_slice(&res.chain_end[1]);
            keccak_oracles_id[8..12].copy_from_slice(&res.chain_end[2]);
            keccak_oracles_id[12..16].copy_from_slice(&res.chain_end[3]);
            keccak_oracles_id[16] = res.chain_end[4][0];
            keccak_oracles_id[17..25].copy_from_slice(&[zeros; 8]);
            // output
            keccak_oracles_id[25..50].copy_from_slice(&res.intermediate_state[0]);
            builder
                .send(channels.keccakf, count, keccak_oracles_id)
                .unwrap();
        }

        // other pushes to the keccakf-channel
        for i in 0..N_WOTS_PUBKEY_KECCAKF_STATES - 1 {
            let mut keccak_oracles_id = [0; 50];
            keccak_oracles_id[0..25].copy_from_slice(&res.xored_intermediate_state[i]);
            keccak_oracles_id[25..50].copy_from_slice(&res.intermediate_state[i + 1]);

            builder
                .send(channels.keccakf, count, keccak_oracles_id)
                .unwrap();
        }

        // final push to the keccakf-channel
        {
            let mut keccak_oracles_id = [0; 50];
            // input
            keccak_oracles_id[0..25]
                .copy_from_slice(&res.xored_intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1]);
            // output
            keccak_oracles_id[25..29].copy_from_slice(&res.wots_public_key);
            keccak_oracles_id[29..50].copy_from_slice(&res.keccak_truncated_bits);
            builder
                .send(channels.keccakf, count, keccak_oracles_id)
                .unwrap();
        }

        // Lookup flushing rule

        for i in 0..N_WOTS_CHUNKS {
            builder
                .receive(channels.lookup_channel, count, {
                    let oracle_ids = [
                        res.chain_length[i],
                        res.chain_length_additive[i],
                        res.lookup_read_timestamp[i],
                    ];
                    oracle_ids
                })
                .unwrap();
            builder
                .send(channels.lookup_channel, count, {
                    let oracle_ids = [
                        res.chain_length[i],
                        res.chain_length_additive[i],
                        res.lookup_write_timestamp[i],
                    ];
                    oracle_ids
                })
                .unwrap();
        }

        builder.pop_namespace();

        res
    }

    fn fill<'arena>(
        &self,
        witness_builder: &mut witness::Builder<'arena>,
        xmss_witnesses: &[XmssVerificationWitness],
    ) {
        let mut chain_length =
            array_init::<_, _, N_WOTS_CHUNKS>(|_| vec![B16::ONE; 1 << self.n_vars]);
        let mut chain_length_additive =
            array_init::<_, _, N_WOTS_CHUNKS>(|_| vec![B16::ZERO; 1 << self.n_vars]);
        let mut chain_end = array_init::<_, _, N_WOTS_CHUNKS>(|_| {
            array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars])
        });
        let mut intermediate_state = array_init::<_, _, N_WOTS_PUBKEY_KECCAKF_STATES>(|_| {
            array_init::<_, _, 25>(|_| vec![B64::ZERO; 1 << self.n_vars])
        });
        let mut xored_intermediate_state = array_init::<_, _, N_WOTS_PUBKEY_KECCAKF_STATES>(|_| {
            array_init::<_, _, 25>(|_| vec![B64::ZERO; 1 << self.n_vars])
        });
        let mut keccak_truncated_bits =
            array_init::<_, _, 21>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut wots_public_key = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut chain_length_additive_packed =
            array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut lookup_read_timestamp =
            array_init::<_, _, N_WOTS_CHUNKS>(|_| vec![B64::ONE; 1 << self.n_vars]);
        let mut lookup_write_timestamp =
            array_init::<_, _, N_WOTS_CHUNKS>(|_| vec![B64::ONE; 1 << self.n_vars]);
        let mut signature_index = vec![B16::ZERO; 1 << self.n_vars];

        chain_length[0]
            .iter_mut()
            .for_each(|v| *v = B16::MULTIPLICATIVE_GENERATOR.pow(VERIFIER_WOTS_HASHES as u64));

        let padding_index = (N_WOTS_CHUNKS * 4) % 17;

        xored_intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][padding_index]
            .iter_mut()
            .for_each(|v| *v += B64::from(KECCAK256_PADDING_LEFT));
        xored_intermediate_state[N_WOTS_PUBKEY_KECCAKF_STATES - 1][16]
            .iter_mut()
            .for_each(|v| *v += B64::from(0x80 << 56));

        let mut lookups_reads = [0; WOTS_CHAIN_SIZE + 1];

        for signature_idx in 0..xmss_witnesses.len() {
            let witness = &xmss_witnesses[signature_idx];
            for wots_chunk in 0..N_WOTS_CHUNKS {
                let chain = &witness.wots.chains[wots_chunk];
                chain_length[wots_chunk][signature_idx] =
                    B16::MULTIPLICATIVE_GENERATOR.pow(chain.len() as u64);
                chain_length_additive[wots_chunk][signature_idx] =
                    B16::from((WOTS_CHAIN_SIZE - chain.len()) as u16);
                fill_rows(
                    &mut chain_end[wots_chunk],
                    signature_idx,
                    witness.wots.chain_heads[wots_chunk],
                );
                for q in 0..N_WOTS_PUBKEY_KECCAKF_STATES {
                    fill_rows(
                        &mut intermediate_state[q],
                        signature_idx,
                        witness.wots.public_key_states[q],
                    );
                }
                fill_rows(
                    &mut keccak_truncated_bits,
                    signature_idx,
                    witness.wots.public_key_states[N_WOTS_PUBKEY_KECCAKF_STATES][4..25]
                        .try_into()
                        .unwrap(),
                );
                fill_rows(
                    &mut wots_public_key,
                    signature_idx,
                    witness.wots.public_key_states[N_WOTS_PUBKEY_KECCAKF_STATES][0..4]
                        .try_into()
                        .unwrap(),
                );
                fill_rows(
                    &mut chain_length_additive_packed,
                    signature_idx,
                    witness.wots.derived_digest,
                );
                signature_index[signature_idx] = B16::from(signature_idx as u16);

                lookup_read_timestamp[wots_chunk][signature_idx] =
                    B64::MULTIPLICATIVE_GENERATOR.pow(lookups_reads[chain.len()]);
                lookups_reads[chain.len()] += 1;
            }

            let mut middle = 17;
            let mut c = 17; // the first 17 * 8 bytes of res.hash are not xored, but directly fed to the keccakf-channel instead
            for i in 0..N_WOTS_PUBKEY_KECCAKF_STATES {
                if i == N_WOTS_PUBKEY_KECCAKF_STATES - 1 {
                    assert_eq!(padding_index, N_WOTS_CHUNKS * 4 - c);
                    middle = padding_index;
                }
                for j in 0..middle {
                    xored_intermediate_state[i][j][signature_idx] += intermediate_state[i][j]
                        [signature_idx]
                        + chain_end[c / 4][c % 4][signature_idx];
                    c += 1;
                }
                for j in middle..25 {
                    xored_intermediate_state[i][j][signature_idx] +=
                        intermediate_state[i][j][signature_idx];
                }
            }
        }

        for wots_chunk in 0..N_WOTS_CHUNKS {
            lookup_write_timestamp[wots_chunk]
                .iter_mut()
                .zip(&lookup_read_timestamp[wots_chunk])
                .for_each(|(w, r)| {
                    *w = *r * B64::MULTIPLICATIVE_GENERATOR;
                });
        }

        fill_multiple_witness_col(witness_builder, self.chain_length, chain_length);
        fill_multiple_witness_col(
            witness_builder,
            self.chain_length_additive,
            chain_length_additive,
        );
        chain_end.into_iter().enumerate().for_each(|(i, cols)| {
            fill_multiple_witness_col(witness_builder, self.chain_end[i], cols);
        });
        intermediate_state
            .into_iter()
            .enumerate()
            .for_each(|(i, cols)| {
                fill_multiple_witness_col(witness_builder, self.intermediate_state[i], cols);
            });
        xored_intermediate_state
            .into_iter()
            .enumerate()
            .for_each(|(i, cols)| {
                fill_multiple_witness_col(witness_builder, self.xored_intermediate_state[i], cols);
            });
        fill_multiple_witness_col(
            witness_builder,
            self.keccak_truncated_bits,
            keccak_truncated_bits,
        );
        fill_multiple_witness_col(witness_builder, self.wots_public_key, wots_public_key);
        fill_multiple_witness_col(
            witness_builder,
            self.chain_length_additive_packed,
            chain_length_additive_packed,
        );
        fill_witness_col(witness_builder, self.signature_index, signature_index);
        fill_multiple_witness_col(
            witness_builder,
            self.lookup_read_timestamp,
            lookup_read_timestamp,
        );
        fill_multiple_witness_col(
            witness_builder,
            self.lookup_write_timestamp,
            lookup_write_timestamp,
        );
    }
}
