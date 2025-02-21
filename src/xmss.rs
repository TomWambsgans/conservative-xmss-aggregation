use std::fmt::Debug;

use array_init::array_init;
use binius_circuits::keccakf::KeccakfState;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;

use crate::{
    config::XMSS_HEIGHT,
    utils::{
        bytes_to_lanes, keccak256, lanes_to_bytes, Hash, KECCAK256_PADDING_LEFT,
        KECCAK256_PADDING_RIGHT,
    },
    wots::{WotsSecretKey, WotsSignature, WotsVerificationError, WotsVerificationWitness},
};

pub type XmssPublicKey = Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmssSecretKey {
    pub wots: Vec<WotsSecretKey>, // length = 1 << H
    pub merkle: Vec<Vec<Hash>>, // merkle tree (leaves = WOTS public keys), length = H, last index is root
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmssSignature {
    pub path: [(Hash, bool); XMSS_HEIGHT], // (a, true) -> hash(a, _), (a, false) -> hash(_, a)
    pub wots_signature: WotsSignature,
}

#[derive(Clone, Debug)]
pub enum XmssVerificationError {
    Wots(WotsVerificationError),
    InvalidMerkleProof,
}

#[derive(Clone, Default)]
pub struct MerkleStepWitness {
    pub aux_at_left: bool,
    pub left: [u64; 4],
    pub right: [u64; 4],
    pub hash: [u64; 4],
    pub keccak_truncated_bits: [u64; 21],
}

#[derive(Clone)]
pub struct XmssVerificationWitness {
    pub wots: WotsVerificationWitness,
    pub merkle_steps: [MerkleStepWitness; XMSS_HEIGHT],
    pub all_keccakf_states: Vec<KeccakfState>, // TODO this is a duplication with other fields
}

impl XmssSecretKey {
    pub fn gen(seed: Hash) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed); // cryptographic randomness

        // use the randomness to derive the 2^H WOTS secret keys
        let wots = (0..1 << XMSS_HEIGHT)
            .map(|_| WotsSecretKey::new(&mut rng))
            .collect::<Vec<_>>();

        // build the merkle tree
        let mut merkle = (0..XMSS_HEIGHT)
            .map(|i| vec![[0u8; 32]; 1 << (XMSS_HEIGHT - i - 1)])
            .collect::<Vec<_>>();
        for j in 0..(1 << XMSS_HEIGHT - 1) {
            merkle[0][j] =
                keccak256(&[wots[j * 2].public_key.0, wots[j * 2 + 1].public_key.0].concat());
        }
        for i in 1..XMSS_HEIGHT {
            for j in 0..(1 << (XMSS_HEIGHT - i - 1)) {
                merkle[i][j] =
                    keccak256(&[merkle[i - 1][j * 2], merkle[i - 1][j * 2 + 1]].concat());
            }
        }
        Self { wots, merkle }
    }

    pub fn public_key(&self) -> Hash {
        self.merkle.last().unwrap()[0]
    }

    pub fn sign(&self, msg_digest: &Hash, mut state: usize) -> XmssSignature {
        assert!(state < 1 << XMSS_HEIGHT);
        let wots_secret = &self.wots[state];
        let wots_signature = wots_secret.sign(msg_digest);
        let mut path = [([0; 32], false); XMSS_HEIGHT];
        let (neighbour, left) = merkle_neighbour(state);
        path[0] = (self.wots[neighbour].public_key.0, left);
        for i in 1..XMSS_HEIGHT {
            state /= 2;
            let (neighbour, left) = merkle_neighbour(state);
            path[i] = (self.merkle[i - 1][neighbour], left);
        }
        XmssSignature {
            path,
            wots_signature,
        }
    }
}

impl XmssSignature {
    pub fn verify(
        &self,
        public_key: &XmssPublicKey,
        msg_digest: &Hash,
    ) -> Result<(), XmssVerificationError> {
        let wots_public_key = self
            .wots_signature
            .verify(msg_digest)
            .map_err(XmssVerificationError::Wots)?;
        let mut hash = wots_public_key.0;
        for (neighbour, left) in &self.path {
            if *left {
                hash = keccak256(&[neighbour.clone(), hash].concat());
            } else {
                hash = keccak256(&[hash, neighbour.clone()].concat());
            }
        }
        if &hash != public_key {
            return Err(XmssVerificationError::InvalidMerkleProof);
        }
        Ok(())
    }

    pub fn verify_with_witness(
        &self,
        public_key: &XmssPublicKey,
        msg_digest: &Hash,
    ) -> Result<XmssVerificationWitness, XmssVerificationError> {
        let mut all_keccakf_states = Vec::new();
        let (wots_witness, _) = self
            .wots_signature
            .verify_with_witness(msg_digest, &mut all_keccakf_states)
            .map_err(XmssVerificationError::Wots)?;
        let mut merkle_steps = array_init(|_| MerkleStepWitness::default());

        let mut state = [0; 25];
        state[0..4].copy_from_slice(&wots_witness.public_key_states.last().unwrap()[0..4]); // wots public key
        for (i, (neighbour, left)) in self.path.iter().enumerate() {
            state[8..25].copy_from_slice(&[0; 17]);
            state[8] = KECCAK256_PADDING_LEFT;
            state[16] = KECCAK256_PADDING_RIGHT;
            if *left {
                let shifted: [u64; 4] = state[0..4].try_into().unwrap();
                state[4..8].copy_from_slice(&shifted);
                state[0..4].copy_from_slice(&bytes_to_lanes::<4>(neighbour));
            } else {
                state[4..8].copy_from_slice(&bytes_to_lanes::<4>(neighbour));
            }

            merkle_steps[i].aux_at_left = *left;
            merkle_steps[i].left = state[0..4].try_into().unwrap();
            merkle_steps[i].right = state[4..8].try_into().unwrap();

            all_keccakf_states.push(KeccakfState(state));
            keccak::f1600(&mut state);

            merkle_steps[i].hash = state[0..4].try_into().unwrap();
            merkle_steps[i].keccak_truncated_bits = state[4..25].try_into().unwrap();
        }

        if &lanes_to_bytes::<200>(&state)[0..32] != public_key {
            return Err(XmssVerificationError::InvalidMerkleProof);
        }

        Ok(XmssVerificationWitness {
            wots: wots_witness,
            merkle_steps,
            all_keccakf_states,
        })
    }
}

impl MerkleStepWitness {
    pub fn main(&self) -> [u64; 4] {
        if self.aux_at_left {
            self.right
        } else {
            self.left
        }
    }

    pub fn aux(&self) -> [u64; 4] {
        if self.aux_at_left {
            self.left
        } else {
            self.right
        }
    }
}

pub fn merkle_neighbour(index: usize) -> (usize, bool) {
    if index % 2 == 0 {
        (index + 1, false)
    } else {
        (index - 1, true)
    }
}

pub fn generate_random_xmss_signatures(
    n_samples: usize,
) -> (Vec<XmssPublicKey>, Vec<Hash>, Vec<XmssSignature>) {
    let data: Vec<_> = (0..n_samples)
        .into_par_iter()
        .map(|i| {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let mut secret_key = [0; 32];
            rng.fill(&mut secret_key);
            let xmss = XmssSecretKey::gen(secret_key);
            let mut msg_digest = [0; 32];
            rng.fill(&mut msg_digest);
            let state = rng.random_range(0..(1 << XMSS_HEIGHT));
            let signature = xmss.sign(&msg_digest, state);
            signature.verify(&xmss.public_key(), &msg_digest).unwrap();
            (xmss.public_key(), msg_digest, signature)
        })
        .collect();

    let public_keys: Vec<_> = data.iter().map(|(pk, _, _)| pk.clone()).collect();
    let msg_digests: Vec<_> = data.iter().map(|(_, md, _)| md.clone()).collect();
    let signatures: Vec<_> = data.iter().map(|(_, _, sig)| sig.clone()).collect();

    (public_keys, msg_digests, signatures)
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_wots_signature() {
        let mut rng = StdRng::seed_from_u64(0);
        let wots = WotsSecretKey::new(&mut rng);
        let mut msg_digest = [0; 32];
        rng.fill(&mut msg_digest);
        let signature = wots.sign(&msg_digest);
        assert_eq!(wots.public_key, signature.verify(&msg_digest).unwrap());
    }

    #[test]
    fn test_xmss_signature() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut all_states = vec![0, (1 << XMSS_HEIGHT) - 1];
        for _ in 0..100 {
            all_states.push(rng.random_range(0..1 << XMSS_HEIGHT));
        }
        let mut secret_key = [0; 32];
        rng.fill(&mut secret_key);
        let xmss = XmssSecretKey::gen(secret_key);
        for state in all_states {
            let mut msg_digest = [0; 32];
            rng.fill(&mut msg_digest);
            let signature = xmss.sign(&msg_digest, state);
            signature.verify(&xmss.public_key(), &msg_digest).unwrap();
        }
    }

    #[test]
    fn test_wots_signature_with_witness() {
        let mut rng = StdRng::seed_from_u64(0);
        let wots = WotsSecretKey::new(&mut rng);
        let mut msg_digest = [0; 32];
        rng.fill(&mut msg_digest);
        let signature = wots.sign(&msg_digest);
        assert_eq!(wots.public_key, signature.verify(&msg_digest).unwrap());
        let (_verif_witness, public_key) = signature
            .verify_with_witness(&msg_digest, &mut Vec::new())
            .unwrap();
        assert_eq!(public_key, wots.public_key);
    }

    #[test]
    fn test_xmss_signature_with_witness() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut all_states = vec![0, (1 << XMSS_HEIGHT) - 1];
        for _ in 0..100 {
            all_states.push(rng.random_range(0..1 << XMSS_HEIGHT));
        }
        let mut secret_key = [0; 32];
        rng.fill(&mut secret_key);
        let xmss = XmssSecretKey::gen(secret_key);
        for state in all_states {
            let mut msg_digest = [0; 32];
            rng.fill(&mut msg_digest);
            let signature = xmss.sign(&msg_digest, state);
            signature.verify(&xmss.public_key(), &msg_digest).unwrap();
            let _verif_witness = signature
                .verify_with_witness(&xmss.public_key(), &msg_digest)
                .unwrap();
        }
    }
}
