use binius_core::constraint_system::channel::{Boundary, FlushDirection};
use binius_field::{BinaryField128b, Field};

use crate::{
    utils::{bytes_to_lanes, B128, MAX_AGGREGATED_SIGNATURES},
    xmss::XmssPublicKey,
};

use super::channels::Channels;
use crate::utils::Hash;

pub fn get_boundaries(
    channels: &Channels,
    public_keys: &[XmssPublicKey],
    msg_digests: &[Hash],
) -> Vec<Boundary<BinaryField128b>> {
    assert_eq!(public_keys.len(), msg_digests.len());
    assert!(public_keys.len() <= MAX_AGGREGATED_SIGNATURES);
    let mut boundaries = Vec::new();
    for (i, public_key) in public_keys.iter().enumerate() {
        let mut values = bytes_to_lanes::<4>(public_key)
            .iter()
            .map(|v| B128::from(*v as u128))
            .collect::<Vec<_>>();
        values.push(B128::from(i as u128)); // signature index
        values.push(B128::ONE); // xmss_depth
        boundaries.push(Boundary {
            channel_id: channels.merkle,
            direction: FlushDirection::Pull,
            values,
            multiplicity: 1,
        });
    }

    for (i, digest) in msg_digests.iter().enumerate() {
        let mut values = bytes_to_lanes::<4>(digest)
            .iter()
            .map(|v| B128::from(*v as u128))
            .collect::<Vec<_>>();
        values.push(B128::from(i as u128)); // signature index
        boundaries.push(Boundary {
            channel_id: channels.message_digest,
            direction: FlushDirection::Pull,
            values,
            multiplicity: 1,
        });
    }

    boundaries
}
