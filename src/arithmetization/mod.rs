use crate::utils::Hash;
use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::constraint_system::channel::Boundary;
use binius_field::BinaryField128b;
use boundaries::get_boundaries;
use channels::Channels;
use tables::{keccakf::KeccakfInfo, Tables};

use crate::xmss::XmssPublicKey;

pub mod boundaries;
pub mod channels;
pub mod tables;

#[allow(dead_code)]
pub struct Arithmetization {
    pub tables: Tables,
    pub channels: Channels,
    pub boundaries: Vec<Boundary<BinaryField128b>>,
}

impl Arithmetization {
    pub fn build<'arena>(
        builder: &mut ConstraintSystemBuilder<'arena>,
        aggregation_count: usize,
        public_keys: &[XmssPublicKey],
        msg_digests: &[Hash],
        keccakf_info: KeccakfInfo,
    ) -> Self {
        let channels = Channels::build(builder);
        let tables = Tables::build(builder, aggregation_count, keccakf_info, &channels);
        let boundaries = get_boundaries(&channels, public_keys, msg_digests);
        Self {
            tables,
            channels,
            boundaries,
        }
    }
}
