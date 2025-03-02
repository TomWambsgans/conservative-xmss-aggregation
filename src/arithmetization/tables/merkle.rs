use array_init::array_init;
use binius_circuits::{
    builder::{witness, ConstraintSystemBuilder},
    transparent,
};
use binius_core::oracle::OracleId;
use binius_field::{BinaryField, Field, PackedField, TowerField};
use binius_math::ArithExpr;

use crate::{
    arithmetization::channels::Channels,
    config::XMSS_HEIGHT,
    utils::{
        fill_multiple_witness_col, fill_rows, fill_witness_col, B1, B128, B16, B64, B8,
        KECCAK256_PADDING_LEFT, KECCAK256_PADDING_RIGHT,
    },
    xmss::XmssVerificationWitness,
};

use super::n_vars_for;

#[derive(Clone, Debug)]
pub struct MerkleTable {
    pub count: usize,
    pub n_vars: usize,
    pub flip: OracleId,                        // 1-bit
    pub pre_hash_left: [OracleId; 4],          // each is 8-bytes
    pub pre_hash_right: [OracleId; 4],         // each is 8-bytes
    pub pre_hash_main: [OracleId; 4],          // each is 8-bytes
    pub pre_hash_aux: [OracleId; 4],           // each is 8-bytes
    pub hash: [OracleId; 4],                   // each is 8-bytes
    pub keccak_truncated_bits: [OracleId; 21], // each is 8-bytes
    pub signature_index: OracleId,             // 2 bytes
    pub xmss_depth: OracleId,                  // 1 bytes
    pub next_xmss_depth: OracleId,             // 1 bytes - virtual
}

impl super::Table for MerkleTable {
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
        builder.push_namespace("merkle_table");
        let count = aggregation_count * XMSS_HEIGHT;
        let n_vars = n_vars_for::<B1>(count);

        let xmss_depth = builder.add_committed("xmss_depth", n_vars, B8::TOWER_LEVEL);
        let res = Self {
            count,
            n_vars,
            flip: builder.add_committed("flip", n_vars, B1::TOWER_LEVEL),
            pre_hash_left: builder.add_committed_multiple(
                "pre_hash_left",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            pre_hash_right: builder.add_committed_multiple(
                "pre_hash_right",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            pre_hash_main: builder.add_committed_multiple(
                "pre_hash_main",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            pre_hash_aux: builder.add_committed_multiple("pre_hash_aux", n_vars, B64::TOWER_LEVEL),
            hash: builder.add_committed_multiple("hash", n_vars, B64::TOWER_LEVEL),
            keccak_truncated_bits: builder.add_committed_multiple(
                "keccak_truncated_bits",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            signature_index: builder.add_committed("signature_index", n_vars, B16::TOWER_LEVEL),
            xmss_depth,
            next_xmss_depth: builder
                .add_linear_combination(
                    "next_xmss_depth",
                    n_vars,
                    [(xmss_depth, B128::from(B8::MULTIPLICATIVE_GENERATOR))],
                )
                .unwrap(),
        };

        // a: pre_hash_main = (1 - flip) . pre_hash_left + flip . pre_hash_right
        // b: pre_hash_main = (1 - flip) . pre_hash_left + flip . pre_hash_right
        for (symbol, arr0, arr1, arr2) in [
            (
                "a",
                res.pre_hash_main,
                res.pre_hash_left,
                res.pre_hash_right,
            ),
            ("b", res.pre_hash_aux, res.pre_hash_right, res.pre_hash_left),
        ] {
            for i in 0..4 {
                builder.assert_zero(
                    format!("merkle-table-constraint-{symbol}-{i}"),
                    [arr0[i], arr1[i], arr2[i], res.flip],
                    ArithExpr::Var(0)
                        - ((ArithExpr::Var(3) - ArithExpr::one()) * ArithExpr::Var(1)
                            + (ArithExpr::Var(3) * (ArithExpr::Var(2)))),
                );
            }
        }

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
        keccak_oracles_id[0..4].copy_from_slice(&res.pre_hash_left);
        keccak_oracles_id[4..8].copy_from_slice(&res.pre_hash_right);
        keccak_oracles_id[8..25].copy_from_slice(&[zeros; 17]);
        keccak_oracles_id[8] = keccak_padding_0x01;
        keccak_oracles_id[16] = keccak_padding_0x80;
        // output
        keccak_oracles_id[25..29].copy_from_slice(&res.hash);
        keccak_oracles_id[29..50].copy_from_slice(&res.keccak_truncated_bits);
        builder
            .send(channels.keccakf, count, keccak_oracles_id)
            .unwrap();

        builder
            .send(channels.merkle, count, {
                let mut oracle_ids = res.hash.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids.push(res.xmss_depth);

                oracle_ids
            })
            .unwrap();

        builder
            .receive(channels.merkle, count, {
                let mut oracle_ids = res.pre_hash_main.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids.push(res.next_xmss_depth);

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
        let mut flip = vec![B8::ZERO; 1 << (self.n_vars - 3)];
        let mut pre_hash_left = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut pre_hash_right = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut pre_hash_main = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut pre_hash_aux = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut hash = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut keccak_truncated_bits =
            array_init::<_, _, 21>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut signature_index = vec![B16::ZERO; 1 << self.n_vars];
        let mut xmss_depth = vec![B8::ZERO; 1 << self.n_vars];
        let mut next_xmss_depth = vec![B8::ZERO; 1 << self.n_vars];

        for signature_idx in 0..xmss_witnesses.len() {
            let witness = &xmss_witnesses[signature_idx];
            for depth in 0..XMSS_HEIGHT {
                let c = signature_idx * XMSS_HEIGHT + depth;
                if witness.merkle_steps[depth].aux_at_left {
                    flip[c / 8] += B8::from(1 << (c % 8));
                }
                fill_rows(&mut pre_hash_left, c, witness.merkle_steps[depth].left);
                fill_rows(&mut pre_hash_right, c, witness.merkle_steps[depth].right);
                fill_rows(&mut pre_hash_main, c, witness.merkle_steps[depth].main());
                fill_rows(&mut pre_hash_aux, c, witness.merkle_steps[depth].aux());
                fill_rows(&mut hash, c, witness.merkle_steps[depth].hash);
                fill_rows(
                    &mut keccak_truncated_bits,
                    c,
                    witness.merkle_steps[depth].keccak_truncated_bits,
                );
                signature_index[c] = B16::from(signature_idx as u16);
                xmss_depth[c] = B8::MULTIPLICATIVE_GENERATOR.pow((XMSS_HEIGHT - 1 - depth) as u64);
                next_xmss_depth[c] = B8::MULTIPLICATIVE_GENERATOR.pow((XMSS_HEIGHT - depth) as u64);
            }
        }

        witness_builder
            .new_column::<B1>(self.flip)
            .as_mut_slice::<B8>()
            .copy_from_slice(&flip);
        fill_multiple_witness_col(witness_builder, self.pre_hash_left, pre_hash_left);
        fill_multiple_witness_col(witness_builder, self.pre_hash_right, pre_hash_right);
        fill_multiple_witness_col(witness_builder, self.pre_hash_main, pre_hash_main);
        fill_multiple_witness_col(witness_builder, self.pre_hash_aux, pre_hash_aux);
        fill_multiple_witness_col(witness_builder, self.hash, hash);
        fill_multiple_witness_col(
            witness_builder,
            self.keccak_truncated_bits,
            keccak_truncated_bits,
        );
        fill_witness_col(witness_builder, self.signature_index, signature_index);
        fill_witness_col(witness_builder, self.xmss_depth, xmss_depth);
        fill_witness_col(witness_builder, self.next_xmss_depth, next_xmss_depth);
    }
}
