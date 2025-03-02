use binius_circuits::builder::{types::F, witness, ConstraintSystemBuilder};
use binius_field::TowerField;
use chain_heads::ChainHeadTable;
use chain_tails::ChainTailTable;
use derived_digest::DerivedDigestTable;
use hash_chain::HashChainTable;
use keccakf::{KeccakFTable, KeccakfInfo};
use lookup::LookupTable;
use merkle::MerkleTable;

use crate::xmss::XmssVerificationWitness;

use super::channels::Channels;

pub mod chain_heads;
pub mod chain_tails;
pub mod derived_digest;
pub mod hash_chain;
pub mod keccakf;
pub mod lookup;
pub mod merkle;

/*
Note:
We cannot implement the `Table` trait on `KecakFTable`, because it required the keccak states when building the table in prover mode (to comply with `binius_circuits`)
*/
#[allow(dead_code)]
pub trait Table {
    // number of relevant rows
    fn count(&self) -> usize;
    // we must count <= have 2^n_vars
    fn n_vars(&self) -> usize;
    // used by both verifier and prover
    fn build<'arena>(
        builder: &mut ConstraintSystemBuilder<'arena>,
        channels: &Channels,
        aggregation_count: usize,
    ) -> Self;
    // used by prover only
    fn fill<'a>(
        &self,
        witness_builder: &mut witness::Builder<'a>,
        xmss_witnesses: &[XmssVerificationWitness],
    );
}

#[derive(Clone, Debug)]
pub struct Tables {
    pub keccakf_table: KeccakFTable,
    pub merkle_table: MerkleTable,
    pub hash_chain_table: HashChainTable,
    pub chain_tail_table: ChainTailTable,
    pub chain_end_table: ChainHeadTable,
    pub lookup_table: LookupTable,
    pub derived_digest_table: DerivedDigestTable,
}

impl Tables {
    pub fn build<'arena>(
        builder: &mut ConstraintSystemBuilder<'arena>,
        aggregation_count: usize,
        keccakf_info: KeccakfInfo,
        channels: &Channels,
    ) -> Self {
        Self {
            keccakf_table: KeccakFTable::build(builder, keccakf_info, &channels),
            merkle_table: MerkleTable::build(builder, &channels, aggregation_count),
            hash_chain_table: HashChainTable::build(builder, &channels, aggregation_count),
            chain_tail_table: ChainTailTable::build(builder, &channels, aggregation_count),
            chain_end_table: ChainHeadTable::build(builder, &channels, aggregation_count),
            lookup_table: LookupTable::build(builder, &channels, aggregation_count),
            derived_digest_table: DerivedDigestTable::build(builder, &channels, aggregation_count),
        }
    }

    pub fn fill<'arena>(
        &self,
        witness_builder: &mut witness::Builder<'arena>,
        xmss_witnesses: &[XmssVerificationWitness],
    ) {
        self.keccakf_table.fill();
        self.merkle_table.fill(witness_builder, xmss_witnesses);
        self.hash_chain_table.fill(witness_builder, xmss_witnesses);
        self.chain_tail_table.fill(witness_builder, xmss_witnesses);
        self.chain_end_table.fill(witness_builder, xmss_witnesses);
        self.derived_digest_table
            .fill(witness_builder, xmss_witnesses);
        self.lookup_table.fill(witness_builder, xmss_witnesses);
    }
}

fn n_vars_for<SmallestTower: TowerField>(count: usize) -> usize {
    (F::TOWER_LEVEL - SmallestTower::TOWER_LEVEL + 1)
        .max(count.next_power_of_two().trailing_zeros() as usize)
}
