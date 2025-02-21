use crate::{
    config::{W, WOTS_FIXED_SUM},
    utils::{
        bytes_to_lanes, keccak256, lanes_to_bytes, Hash, KECCAK256_PADDING_LEFT,
        KECCAK256_PADDING_RIGHT, N_WOTS_CHUNKS, N_WOTS_PUBKEY_KECCAKF_STATES, WOTS_CHAIN_SIZE,
    },
};
use array_init::array_init;
use binius_circuits::keccakf::KeccakfState;
use rand::Rng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WotsPublicKey(pub Hash);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WotsSecretKey {
    pub pre_images: [Hash; N_WOTS_CHUNKS],
    pub public_key: WotsPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WotsSignature {
    pub nonce: u64, // used to get correct checksum on the derived message digest
    pub hashes: [Hash; N_WOTS_CHUNKS],
}

#[derive(Clone, Debug, Default)]
pub struct WotsChainStepWitness {
    pub pre: [u64; 4],
    pub hash: [u64; 4],
    pub keccak_truncated_bits: [u64; 21],
}

#[derive(Clone, Debug)]
pub enum WotsVerificationError {
    InvalidChecksum,
}

#[derive(Clone, Debug)]
pub struct WotsVerificationWitness {
    pub chain_tails: Vec<[u64; 4]>, // length = WOTS_CHUNKS
    pub chains: [Vec<WotsChainStepWitness>; N_WOTS_CHUNKS],
    pub chain_heads: Vec<[u64; 4]>, // length = WOTS_CHUNKS
    pub public_key_states: [[u64; 25]; N_WOTS_PUBKEY_KECCAKF_STATES + 1], // wots public key if 4 first u64 of last state
    // msg digest
    pub msg_digest: [u64; 4],
    pub nonce: u64,
    pub derived_digest: [u64; 4],
    pub derived_digest_keccak_truncated_bits: [u64; 21],
    pub derived_digest_chuncks: [usize; N_WOTS_CHUNKS],
}

impl WotsSecretKey {
    /// R should be a cryptographically secure pseudo-random generator
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let mut pre_images = [[0u8; 32]; N_WOTS_CHUNKS];
        pre_images
            .iter_mut()
            .for_each(|pre_im| rng.fill_bytes(pre_im));

        let mut buff = [0u8; N_WOTS_CHUNKS * 32];
        for i in 0..N_WOTS_CHUNKS {
            buff[32 * i..32 * (i + 1)].copy_from_slice(&pre_images[i]);
        }
        for i in 0..N_WOTS_CHUNKS {
            for _ in 0..WOTS_CHAIN_SIZE {
                let hash = keccak256(&buff[32 * i..32 * (i + 1)]);
                buff[32 * i..32 * (i + 1)].copy_from_slice(&hash);
            }
        }
        let public_key = WotsPublicKey(keccak256(&buff));
        Self {
            pre_images,
            public_key,
        }
    }

    pub fn sign(&self, msg_digest: &Hash) -> WotsSignature {
        for nonce in 0..u64::MAX {
            let derived_digest = derive_digest(msg_digest, nonce);
            if checksum(&derived_digest) != WOTS_FIXED_SUM {
                continue;
            }
            let mut hashes = self.pre_images.clone();
            for (i, target) in split_chuncks(&derived_digest).into_iter().enumerate() {
                for _ in 0..target {
                    hashes[i] = keccak256(&hashes[i]);
                }
            }
            return WotsSignature { hashes, nonce };
        }
        panic!("(very) unlucky");
    }
}

impl WotsSignature {
    // returns the expected public_key, which needs to be checked subsequentially
    pub fn verify(&self, msg_digest: &Hash) -> Result<WotsPublicKey, WotsVerificationError> {
        let derived_digest = derive_digest(&msg_digest, self.nonce);
        if checksum(&derived_digest) != WOTS_FIXED_SUM {
            return Err(WotsVerificationError::InvalidChecksum);
        }
        let split = split_chuncks(&derived_digest);
        let mut hashes = self.hashes.clone();
        for (i, target) in split.into_iter().enumerate() {
            for _ in 0..WOTS_CHAIN_SIZE - target {
                hashes[i] = keccak256(&hashes[i]);
            }
        }
        Ok(WotsPublicKey(keccak256(&hashes.concat())))
    }

    // returns the expected public_key, which needs to be subsequentially checked
    pub fn verify_with_witness(
        &self,
        msg_digest: &Hash,
        all_keccakf_permutations: &mut Vec<KeccakfState>,
    ) -> Result<(WotsVerificationWitness, WotsPublicKey), WotsVerificationError> {
        let mut derive_digest_state = [0; 25];
        derive_digest_state[0..4].copy_from_slice(&bytes_to_lanes::<4>(msg_digest));
        derive_digest_state[4] = self.nonce;
        derive_digest_state[5] = KECCAK256_PADDING_LEFT;
        derive_digest_state[16] = KECCAK256_PADDING_RIGHT;

        all_keccakf_permutations.push(KeccakfState(derive_digest_state));
        keccak::f1600(&mut derive_digest_state);

        let derived_digest = lanes_to_bytes::<32>(&derive_digest_state[0..4]);

        if checksum(&derived_digest) != WOTS_FIXED_SUM {
            return Err(WotsVerificationError::InvalidChecksum);
        }

        let mut chains = array_init::<_, _, N_WOTS_CHUNKS>(|_| Vec::new());

        let mut chain_heads = Vec::<[u64; 4]>::new();
        let mut chain_tails = Vec::<[u64; 4]>::new();

        let derived_digest_chuncks = split_chuncks(&derived_digest);

        for (i, target) in derived_digest_chuncks.into_iter().enumerate() {
            chain_tails.push(bytes_to_lanes(&self.hashes[i]));
            let mut state = [0; 25];
            state[0..4].copy_from_slice(&chain_tails[i]);
            state[4] = KECCAK256_PADDING_LEFT;
            state[16] = KECCAK256_PADDING_RIGHT;
            for _ in 0..WOTS_CHAIN_SIZE - target {
                let mut chain_step = WotsChainStepWitness::default();
                chain_step.pre = state[0..4].try_into().unwrap();

                all_keccakf_permutations.push(KeccakfState(state));
                keccak::f1600(&mut state);

                chain_step.hash = state[0..4].try_into().unwrap();
                chain_step.keccak_truncated_bits = state[4..25].try_into().unwrap();
                chains[i].push(chain_step);
                for j in 4..25 {
                    state[j] = 0;
                }
                state[4] = KECCAK256_PADDING_LEFT;
                state[16] = KECCAK256_PADDING_RIGHT;
            }
            chain_heads.push(state[0..4].try_into().unwrap());
        }

        let mut public_key_states = [[0; 25]; N_WOTS_PUBKEY_KECCAKF_STATES + 1];

        let mut state = [0; 25];
        state[0..4].copy_from_slice(&chain_heads[0]);
        state[4..8].copy_from_slice(&chain_heads[1]);
        state[8..12].copy_from_slice(&chain_heads[2]);
        state[12..16].copy_from_slice(&chain_heads[3]);
        state[16] = chain_heads[4][0];

        let mut c = 17;
        for i in 0..=N_WOTS_PUBKEY_KECCAKF_STATES {
            all_keccakf_permutations.push(KeccakfState(state));
            keccak::f1600(&mut state);

            public_key_states[i] = state;

            if i == N_WOTS_PUBKEY_KECCAKF_STATES {
                break;
            }
            for j in 0..17 {
                state[j] ^= chain_heads[c / 4][c % 4];
                c += 1;
                if c == N_WOTS_CHUNKS * 4 {
                    assert!(j + 1 < 17);
                    assert!(i == N_WOTS_PUBKEY_KECCAKF_STATES - 1);
                    state[j + 1] ^= KECCAK256_PADDING_LEFT;
                    state[16] ^= KECCAK256_PADDING_RIGHT;
                    break;
                }
            }
        }

        let public_key = WotsPublicKey(lanes_to_bytes::<200>(&state)[0..32].try_into().unwrap());

        Ok((
            WotsVerificationWitness {
                chains,
                chain_tails,
                chain_heads,
                public_key_states,
                msg_digest: bytes_to_lanes(msg_digest),
                nonce: self.nonce,
                derived_digest: derive_digest_state[0..4].try_into().unwrap(),
                derived_digest_keccak_truncated_bits: derive_digest_state[4..25]
                    .try_into()
                    .unwrap(),
                derived_digest_chuncks,
            },
            public_key,
        ))
    }
}

fn split_chuncks(derived_digest: &Hash) -> [usize; N_WOTS_CHUNKS] {
    // interpret each chunk of W bits as a little-endian integer
    let mut res = [0; N_WOTS_CHUNKS];
    for (i, start_bit) in (0..256).step_by(W).enumerate() {
        let mut chunk_val: u64 = 0;
        for bit in 0..W {
            let bit_index = start_bit + bit;
            let byte_index = bit_index / 8;
            let bit_in_byte = bit_index % 8;
            let bit_val = (derived_digest[byte_index] >> bit_in_byte) & 1;
            chunk_val |= (bit_val as u64) << bit;
        }
        res[i] = chunk_val as usize;
    }
    res
}

fn checksum(derived_digest: &Hash) -> usize {
    split_chuncks(derived_digest).into_iter().sum()
}

pub fn derive_digest(msg_digest: &Hash, nonce: u64) -> Hash {
    keccak256(&[msg_digest.to_vec(), nonce.to_le_bytes().to_vec()].concat())
}
