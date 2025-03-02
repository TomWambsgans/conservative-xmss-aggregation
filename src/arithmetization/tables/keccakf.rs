use binius_circuits::{builder::ConstraintSystemBuilder, keccakf::KeccakfState};
use binius_core::oracle::OracleId;

use super::n_vars_for;
use crate::{arithmetization::channels::Channels, utils::B64};

pub enum KeccakfInfo {
    ProverMode(Vec<KeccakfState>),
    VerifierMode { total_keccakf_count: usize },
}

impl KeccakfInfo {
    pub fn total_keccakf_count(&self) -> usize {
        match self {
            Self::ProverMode(states) => states.len(),
            Self::VerifierMode {
                total_keccakf_count,
            } => *total_keccakf_count,
        }
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct KeccakFTable {
    pub count: usize,
    pub n_vars: usize,
    pub input: [OracleId; 25],  // each is 8-bytes
    pub output: [OracleId; 25], // each is 8-bytes
}

impl KeccakFTable {
    pub fn build<'arena>(
        builder: &mut ConstraintSystemBuilder<'arena>,
        keccakf_info: KeccakfInfo,
        channels: &Channels,
    ) -> Self {
        builder.push_namespace("keccak_f_table");
        let count = keccakf_info.total_keccakf_count();
        let n_vars = n_vars_for::<B64>(count); // Not sure of B64 here
        let binius_circuits::keccakf::KeccakfOracles { input, output } =
            binius_circuits::keccakf::keccakf(
                builder,
                &match &keccakf_info {
                    KeccakfInfo::ProverMode(states) => Some(states),
                    KeccakfInfo::VerifierMode { .. } => None,
                },
                n_vars,
            )
            .unwrap();

        builder
            .receive(channels.keccakf, count, [input, output].concat())
            .unwrap();

        builder.pop_namespace();

        Self {
            count,
            n_vars,
            input,
            output,
        }
    }

    pub fn fill(&self) {
        // already done above by `binius_circuits::keccakf::keccakf`
    }
}
