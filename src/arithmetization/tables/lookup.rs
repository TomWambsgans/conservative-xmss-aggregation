use binius_circuits::{
    builder::{witness, ConstraintSystemBuilder},
    transparent,
};
use binius_core::oracle::OracleId;
use binius_field::{BinaryField, Field, PackedField, TowerField};

use super::n_vars_for;
use crate::{
    arithmetization::channels::Channels,
    utils::{fill_witness_col, B16, B64, N_WOTS_CHUNKS, WOTS_CHAIN_SIZE},
    xmss::XmssVerificationWitness,
};

#[derive(Clone, Debug)]
pub struct LookupTable {
    pub count: usize,
    pub n_vars: usize,
    pub final_timestamp: OracleId, // 8-bytes
}

impl super::Table for LookupTable {
    fn count(&self) -> usize {
        self.count
    }

    fn n_vars(&self) -> usize {
        self.n_vars
    }

    fn build<'arena>(
        builder: &mut ConstraintSystemBuilder<'arena>,
        channels: &Channels,
        _: usize,
    ) -> Self {
        builder.push_namespace("lookup_table");
        let count = WOTS_CHAIN_SIZE + 1;
        let n_vars = n_vars_for::<B16>(count);
        let res = Self {
            count,
            n_vars,
            final_timestamp: builder.add_committed(
                "lookup_final_timestamp",
                n_vars,
                B64::TOWER_LEVEL,
            ),
        };

        let chain_length_mul =
            binius_circuits::transparent::make_transparent(builder, "chain_length_mul", &{
                let mut values = vec![B16::ZERO; 1 << n_vars];
                for i in 0..=WOTS_CHAIN_SIZE {
                    values[i] = B16::MULTIPLICATIVE_GENERATOR.pow(i as u64);
                }
                values
            })
            .unwrap();

        let chain_length_add =
            binius_circuits::transparent::make_transparent(builder, "chain_length_add", &{
                let mut values = vec![B16::ZERO; 1 << n_vars];
                for i in 0..=WOTS_CHAIN_SIZE {
                    values[i] = B16::from((WOTS_CHAIN_SIZE - i) as u16);
                }
                values
            })
            .unwrap();

        let ones = transparent::constant(builder, "ones", n_vars, B64::ONE).unwrap();

        builder
            .receive(channels.lookup_channel, count, {
                let oracle_ids = [chain_length_mul, chain_length_add, res.final_timestamp];
                oracle_ids
            })
            .unwrap();

        builder
            .send(channels.lookup_channel, count, {
                let oracle_ids = [chain_length_mul, chain_length_add, ones];
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
        let mut final_timestamps = [0; WOTS_CHAIN_SIZE + 1];
        for xmss_witnesses in xmss_witnesses {
            for chunk in 0..N_WOTS_CHUNKS {
                let n_verifier_hashes =
                    WOTS_CHAIN_SIZE - xmss_witnesses.wots.derived_digest_chuncks[chunk];
                final_timestamps[n_verifier_hashes] += 1;
            }
        }

        let mut final_timestamps_col = vec![B64::ZERO; 1 << self.n_vars];
        for (i, v) in final_timestamps.iter().enumerate() {
            final_timestamps_col[i] = B64::MULTIPLICATIVE_GENERATOR.pow(*v as u64);
        }

        fill_witness_col(witness_builder, self.final_timestamp, final_timestamps_col);
    }
}
