use std::time::Duration;

use binius_circuits::builder::witness;
use binius_core::oracle::OracleId;
use binius_field::{as_packed_field::PackScalar, *};
use tiny_keccak::{Hasher, Keccak};

use crate::config::{W, WOTS_FIXED_SUM};

pub type B1 = BinaryField1b;
pub type B8 = BinaryField8b;
pub type B16 = BinaryField16b;
pub type B64 = BinaryField64b;
pub type B128 = BinaryField128b;

pub type Hash = [u8; 32];

// Number of intermediate states inside keccak256's sponge construction when computing the WOTS public key.
// (WOTS public key = hash of N_WOTS_CHUNKS consecutive other hashes (heads of each hash chain))
// Example: W = 8. we need to hash 256 / 8 = 32 consecutives hashes. Each hash occupies 4 lanes of 8-bytes -> 128 lanes. +1 for padding -> 129 lanes.
// keccak256 rate = 17 lanes. 129 = 7 * 17 + 10 -> 8 keccak-f permuation, 7 intermediate states. So N_WOTS_PUBKEY_KECCAKF_STATES = 7
pub const N_WOTS_PUBKEY_KECCAKF_STATES: usize = (N_WOTS_CHUNKS * 4 + 1).div_ceil(17) - 1;
// number of chunck per WOTS signature
pub const N_WOTS_CHUNKS: usize = 256 / W;
pub const WOTS_CHAIN_SIZE: usize = (1 << W) - 1;
// total number of hashes when verifying a WOTS signature. This does not take into account the final hash to retrieve the public key.
pub const VERIFIER_WOTS_HASHES: usize = N_WOTS_CHUNKS * WOTS_CHAIN_SIZE - WOTS_FIXED_SUM;
pub const MAX_AGGREGATED_SIGNATURES: usize = 1 << (2 * 8); // we use 2 bytes in arithmetization to represent the signature index

pub const KECCAK256_PADDING_LEFT: u64 = 0x01;
pub const KECCAK256_PADDING_RIGHT: u64 = 0x80 << 56;

// sanity checks
const _: () = {
    assert!(W.is_power_of_two(), "Binius uses towers of binary fields.");
    assert!(
        WOTS_CHAIN_SIZE * N_WOTS_CHUNKS <= 1 << (2 * 8),
        "we use 2 byte in arithmetization to compute th sum of each WOTS chunk"
    );
};

pub fn keccak256(data: &[u8]) -> Hash {
    let mut h = Keccak::v256();
    h.update(data);
    let mut r = [0u8; 32];
    h.finalize(&mut r);
    r
}

pub fn lanes_to_bytes<const N: usize>(state: &[u64]) -> [u8; N] {
    assert_eq!(state.len() * 8, N);
    let mut output = [0u8; N];
    for i in 0..state.len() {
        let word = state[i];
        for j in 0..8 {
            let idx = i * 8 + j;
            output[idx] = ((word >> (8 * j)) & 0xFF) as u8;
        }
    }
    output
}

pub fn bytes_to_lanes<const N: usize>(input: &[u8]) -> [u64; N] {
    assert_eq!(input.len(), 8 * N);
    let mut state = [0; N];
    for (i, chunk) in input.chunks(8).enumerate() {
        let mut word = 0;
        for (j, &byte) in chunk.iter().enumerate() {
            word |= (byte as u64) << (8 * j);
        }
        state[i] = word;
    }
    state
}

pub fn fill_witness_col<'a, FS: TowerField>(
    witness_builder: &mut witness::Builder<'a>,
    id: OracleId,
    data: Vec<FS>,
) where
    binius_field::arch::OptimalUnderlier: PackScalar<FS>,
    binius_field::BinaryField128b: ExtensionField<FS>,
    FS: bytemuck::Pod,
{
    witness_builder
        .new_column::<FS>(id)
        .as_mut_slice::<FS>()
        .copy_from_slice(&data);
}

pub fn fill_multiple_witness_col<'a, FS: TowerField, const N: usize>(
    witness_builder: &mut witness::Builder<'a>,
    id: [OracleId; N],
    data: [Vec<FS>; N],
) where
    binius_field::arch::OptimalUnderlier: PackScalar<FS>,
    binius_field::BinaryField128b: ExtensionField<FS>,
    FS: bytemuck::Pod,
{
    id.into_iter().zip(data.into_iter()).for_each(|(id, data)| {
        fill_witness_col(witness_builder, id, data);
    });
}

pub fn fill_rows<const N: usize, T: Copy>(cols: &mut [Vec<B64>; N], row: usize, values: [T; N])
where
    B64: From<T>,
{
    for i in 0..N {
        cols[i][row] = B64::from(values[i]);
    }
}

pub fn format_duration(duration: Duration) -> String {
    format!("{:?}", Duration::from_millis(duration.as_millis() as u64))
}
