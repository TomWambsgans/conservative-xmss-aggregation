use binius_circuits::{
    builder::{witness, ConstraintSystemBuilder},
    transparent,
};
use binius_core::oracle::OracleId;
use binius_field::{BinaryField, Field, PackedField, TowerField};

use super::n_vars_for;
use crate::{
    arithmetization::channels::Channels,
    utils::{
        fill_multiple_witness_col, fill_rows, fill_witness_col, B128, B16, B64, B8,
        KECCAK256_PADDING_LEFT, KECCAK256_PADDING_RIGHT, N_WOTS_CHUNKS, VERIFIER_WOTS_HASHES,
    },
    xmss::XmssVerificationWitness,
};
use array_init::array_init;

#[derive(Clone, Debug)]
pub struct HashChainTable {
    pub count: usize,
    pub n_vars: usize,
    pub pre_hash: [OracleId; 4],               // each is 8-bytes
    pub hash: [OracleId; 4],                   // each is 8-bytes
    pub keccak_truncated_bits: [OracleId; 21], // each is 8-bytes
    pub signature_index: OracleId,             // 2 bytes
    pub chain_length: OracleId,                // 2 bytes
    pub next_chain_length: OracleId,           // 2 bytes -  virtual
    pub wots_chunk_index: OracleId,            // 1 bytes
}

impl super::Table for HashChainTable {
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
        builder.push_namespace("hash_chain_table");
        let count = aggregation_count * VERIFIER_WOTS_HASHES;
        let n_vars = n_vars_for::<B8>(count);

        let chain_length = builder.add_committed("chain_length", n_vars, B16::TOWER_LEVEL);
        let res = Self {
            count,
            n_vars,
            pre_hash: builder.add_committed_multiple("pre_hash", n_vars, B64::TOWER_LEVEL),
            hash: builder.add_committed_multiple("hash", n_vars, B64::TOWER_LEVEL),
            keccak_truncated_bits: builder.add_committed_multiple(
                "keccak_truncated_bits",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            signature_index: builder.add_committed("signature_index", n_vars, B16::TOWER_LEVEL),
            chain_length,
            next_chain_length: builder
                .add_linear_combination(
                    "next_chain_length",
                    n_vars,
                    [(chain_length, B128::from(B16::MULTIPLICATIVE_GENERATOR))],
                )
                .unwrap(),
            wots_chunk_index: builder.add_committed("wots_chunk_index", n_vars, B8::TOWER_LEVEL),
        };

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

        let mut keccak_oracles_id = [0; 50];
        // input
        keccak_oracles_id[0..4].copy_from_slice(&res.pre_hash);
        keccak_oracles_id[4..25].copy_from_slice(&[zeros; 21]);
        keccak_oracles_id[4] = keccak_padding_0x01;
        keccak_oracles_id[16] = keccak_padding_0x80;
        // output
        keccak_oracles_id[25..29].copy_from_slice(&res.hash);
        keccak_oracles_id[29..50].copy_from_slice(&res.keccak_truncated_bits);
        builder
            .send(channels.keccakf, count, keccak_oracles_id)
            .unwrap();

        builder
            .send(channels.hash_chain_counter, count, {
                let mut oracle_ids = res.hash.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids.push(res.next_chain_length);
                oracle_ids.push(res.wots_chunk_index);

                oracle_ids
            })
            .unwrap();

        builder
            .receive(channels.hash_chain_counter, count, {
                let mut oracle_ids = res.pre_hash.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids.push(res.chain_length);
                oracle_ids.push(res.wots_chunk_index);

                oracle_ids
            })
            .unwrap();

        builder.pop_namespace();

        res
    }

    fn fill<'arena>(
        &self,
        witness_builder: &mut witness::Builder<'arena>,
        xmss_witnesses: &[XmssVerificationWitness],
    ) {
        let mut pre_hash = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut hash = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut keccak_truncated_bits =
            array_init::<_, _, 21>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut signature_index = vec![B16::ZERO; 1 << self.n_vars];
        let mut chain_length = vec![B16::ZERO; 1 << self.n_vars];
        let mut next_chain_length = vec![B16::ZERO; 1 << self.n_vars];
        let mut wots_chunk_index = vec![B8::ZERO; 1 << self.n_vars];

        let mut c = 0;
        for signature_idx in 0..xmss_witnesses.len() {
            let witness = &xmss_witnesses[signature_idx];
            for wots_chunk in 0..N_WOTS_CHUNKS {
                let chain = &witness.wots.chains[wots_chunk];
                for (idx_in_chain, step) in chain.iter().enumerate() {
                    fill_rows(&mut pre_hash, c, step.pre);
                    fill_rows(&mut hash, c, step.hash);
                    fill_rows(&mut keccak_truncated_bits, c, step.keccak_truncated_bits);
                    signature_index[c] = B16::from(signature_idx as u16);
                    chain_length[c] = B16::MULTIPLICATIVE_GENERATOR.pow(idx_in_chain as u64);
                    next_chain_length[c] =
                        B16::MULTIPLICATIVE_GENERATOR.pow((idx_in_chain + 1) as u64);
                    wots_chunk_index[c] = B8::from(wots_chunk as u8);

                    c += 1;
                }
            }
        }

        fill_multiple_witness_col(witness_builder, self.pre_hash, pre_hash);
        fill_multiple_witness_col(witness_builder, self.hash, hash);
        fill_multiple_witness_col(
            witness_builder,
            self.keccak_truncated_bits,
            keccak_truncated_bits,
        );
        fill_witness_col(witness_builder, self.signature_index, signature_index);
        fill_witness_col(witness_builder, self.chain_length, chain_length);
        fill_witness_col(witness_builder, self.next_chain_length, next_chain_length);
        fill_witness_col(witness_builder, self.wots_chunk_index, wots_chunk_index);
    }
}
