use array_init::array_init;
use binius_circuits::{
    builder::{witness, ConstraintSystemBuilder},
    transparent,
};
use binius_core::oracle::OracleId;
use binius_field::{Field, TowerField};

use super::n_vars_for;
use crate::{
    arithmetization::channels::Channels,
    utils::{fill_multiple_witness_col, fill_rows, fill_witness_col, B16, B64, B8, N_WOTS_CHUNKS},
    xmss::XmssVerificationWitness,
};

#[derive(Clone, Debug)]
pub struct ChainTailTable {
    pub count: usize,
    pub n_vars: usize,
    pub first_pre_hash: [OracleId; 4], // each is 8-bytes
    pub signature_index: OracleId,     // 2 bytes
    pub wots_chunk_index: OracleId,    // 1 bytes
}

impl super::Table for ChainTailTable {
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
        builder.push_namespace("chain_tail_table");
        let count = aggregation_count * N_WOTS_CHUNKS;
        let n_vars = n_vars_for::<B8>(count);

        let res = Self {
            count,
            n_vars,
            first_pre_hash: builder.add_committed_multiple(
                "first_pre_hash",
                n_vars,
                B64::TOWER_LEVEL,
            ),
            signature_index: builder.add_committed("signature_index", n_vars, B16::TOWER_LEVEL),
            wots_chunk_index: builder.add_committed("wots_chunk_index", n_vars, B8::TOWER_LEVEL),
        };

        let ones = transparent::constant(builder, "ones", n_vars, B64::ONE).unwrap();

        builder
            .send(channels.hash_chain_counter, count, {
                let mut oracle_ids = res.first_pre_hash.to_vec();
                oracle_ids.push(res.signature_index);
                oracle_ids.push(ones);
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
        let mut first_pre_hash = array_init::<_, _, 4>(|_| vec![B64::ZERO; 1 << self.n_vars]);
        let mut signature_index = vec![B16::ZERO; 1 << self.n_vars];
        let mut wots_chunk_index = vec![B8::ZERO; 1 << self.n_vars];

        for signature_idx in 0..xmss_witnesses.len() {
            let witness = &xmss_witnesses[signature_idx];
            for wots_chunk in 0..N_WOTS_CHUNKS {
                let c = signature_idx * N_WOTS_CHUNKS + wots_chunk;
                fill_rows(&mut first_pre_hash, c, witness.wots.chain_tails[wots_chunk]);
                signature_index[c] = B16::from(signature_idx as u16);
                wots_chunk_index[c] = B8::from(wots_chunk as u8);
            }
        }

        fill_multiple_witness_col(witness_builder, self.first_pre_hash, first_pre_hash);
        fill_witness_col(witness_builder, self.signature_index, signature_index);
        fill_witness_col(witness_builder, self.wots_chunk_index, wots_chunk_index);
    }
}
