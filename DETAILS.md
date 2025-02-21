# Cryptography

## WOTS

For simplicity, we do not use WOTS+.

We use the fixed sum technique from [SPHINCS+C:](https://eprint.iacr.org/2022/778.pdf):

Private key consists in 256/W values of 32 bytes each: s1, s2, ...
Public key = keccak256(p1, p2, ...) where pi = keccak256(keccak256( ... keccak256(pi))) (iterated 2^W - 1 times)

When signing a message_digest, Alice must find a nonce such that the "derived_digest" (= keccak256(message_digest, nonce)) has a correct checksum WOTS_FIXED_SUM.

Then, to sign the derived digest, Alice splits it into chunks of W bits, and obtain 256/W integers of W-bits: m1, m2, ...

The signature consists in: z1, z2, ..., where zi = keccak256(keccak256( ... keccak256(pi))) (iterated mi times)

## XMSS

A merkle tree where leaves are WOTS public key, of height XMSS_HEIGHT.
Number of signatures available = 2^XMSS_HEIGHT


# M3 Arithmetization - XMSS (keccak256) Aggregation

An introduction to M3: [m3-tutorial](https://www.binius.xyz/basics/arithmetization/m3/)

## Notations

- generator8, generator16, generator64 are fixed multiplicative generator of GF(2^8) \ {0}, GF(2^16) \ {0}, GF(2^64) \ {0}
- NS: number of signatures to aggregate
- WOTS_CHUNKS = 256 / W (number of WOTS chunck)

## Tables

### The Keccak-f-table

#### Length

The total number of keccak-f permutations, a parameter which is carried in the aggregation proof.

#### Columns

- input: 25 x 8-bytes
- output: 25 x 8-bytes

#### Constraints

- cf `binius_circuits::keccakf::keccakf`

#### Flushing rules

- Pull the tuple (input, output) from the keccak-f-channel


### The merkle-table

#### Length

NS * XMSS_HEIGHT

#### Columns

- flip: 1-bit
- pre_hash_left: 4 x 8-bytes
- pre_hash_right: 4 x 8-bytes
- pre_hash_main: 4 x 8-bytes
- pre_hash_aux: 4 x 8-bytes
- hash: 4 x 8-bytes
- keccak_truncated_bits: 21 x 8-bytes
- signature_index: 2-bytes
- xmss_depth: 1-byte
- next_xmss_depth: 1-byte (virtual column = xmss_depth x generator8)

#### Constraints:

pre_hash_main = (1 - flip) . pre_hash_left + flip . pre_hash_right
pre_hash_aux = (1 - flip) . pre_hash_right + flip . pre_hash_left

#### Flushing rules

- push (pre_hash_left | pre_hash_right | padding, hash | keccak_truncated_bits) into the keccak-f-channel
- push (hash, signature_index, xmss_depth) into the merkle-channel
- pull (pre_hash_main, signature_index, next_xmss_depth) from the merkle-channel


### The hash-chain-table

#### Length

NS * [WOTS_CHUNKS * (2^W - 1) - WOTS_FIXED_SUM] (Sum of the number of hash required to verify each chunk)

#### Columns

- pre_hash: 4 x 8-bytes
- hash: 4 x 8-bytes
- keccak_truncated_bits: 21 x 8-bytes 
- signature_index: 2-bytes
- chain_length 2-bytes
- next_chain_length: 2-bytes (virtual column = chain_length * generator16)
- wots_chunk_index: 1-byte

#### Flushing rules

- push (pre_hash | padding, hash | keccak_truncated_bits) into the keccak-f-channel
- push (hash, signature_index, next_chain_length, wots_chunk_index) into the hash-chain-counter-channel
- pull (pre_hash, signature_index, chain_length, wots_chunk_index) from the hash-chain-counter-channel

### The chain-tail-table

#### Length

NS * WOTS_CHUNKS

#### Columns

- first_pre_hash: 4 x 8-bytes
- signature_index: 2-bytes 
- wots_chunk_index: 1-byte 

#### Flushing rules

- push (first_pre_hash, signature_index, 1, wots_chunk_index) into the hash-chain-counter-channel


### The chain-head-table

#### Length

NS

#### Columns

- chain_length: (256 / W) x 2-bytes : one column for each WOTS chunck (represents the number of hashes performed by the verifier for a given wots chunk, in multiplicative form)
- chain_length_additive: (256 / W) x 2-bytes : similar to chain_length, but in adititive "reversed" form (chain_length: generator16^X corresponds to  chain_length_additive: 2^W - 1 - X)
- chain_end: (256 / W) x (4 x 8-bytes) : one for each WOTS chunck
- xored_intermediate_state: q x 25 x 8-bytes,  (i = 1, ..., N). q = (WOTS_CHUNKS * 4 + 1).div_ceil(17) - 1
- keccak_truncated_bits: 21 x 8-byte
- wots_public_key: 4 x 8-bytes
- lookup_read_timestamp: (256 / W) x 8 bytes
- signature_index: 2-bytes

#### Constraints

- lookup_read_timestamp never equals zero
- chain_length[0] * chain_length[1] * chain_length[2] ... = generator64^(WOTS_CHUNKS * (2^W - 1) - WOTS_FIXED_SUM)

#### Flushing rules

- for each chunck i, pull (chain_end[i], signature_index, chain_length[i], i) from the hash-chain-counter-channel
- push (wots_public_key, signature_index, generator8^XMSS_HEIGHT) into the merkle-channel
- push ((chain_length_additive[0], chain_length_additive[1], ...), signature_index) into the derived-message-digest-channel (using linear combinations)

- push ((chain_end[0], chain_end[1], ..., chain_end[17], empty, ..., empty), xored_intermediate_state_0) into the keccak-f-channel
- push (xored_intermediate_state_0 ^ (chain_end[17], chain_end[18], ...), xored_intermediate_state_1) into the keccak-f-channel
- push (xored_intermediate_state_1 ^ (chain_end[34], chain_end[35], ...), xored_intermediate_state_2) into the keccak-f-channel
...
- push (xored_intermediate_state_(q-1) ^ (chain_end[-10], chain_end[-9], ... | padding), wots_public_key | keccak_truncated_bits) into the keccak-f-channel (-10 is arbitrary here)

- for all i, pull (chain_length[i], chain_length_additive[i], lookup_read_timestamp[i]) from the lookup-channel
           , push (chain_length[i], chain_length_additive[i], lookup_read_timestamp[i] * generator64) into the lookup-channel


### The lookup-table

#### Length

2^W

#### Columns

- chain_length_mul: 2-bytes  (generator16^X) (transparent)
- chain_length_add: 2-bytes  (2^W - 1 - X) (transparent)
- final_timestamp: 8-bytes

#### Flushing rules

pull (chain_length_mul, chain_length_add, final_timestamp) from the lookup-channel
push (chain_length_mul, chain_length_add, 1) into the lookup-channel


### The derive-digest-table

#### Length

NS

#### Columns

- msg_digest: 4 x 8-bytes
- nonce: 8-bytes
- derived_digest: 4 x 8-bytes
- signature_index: 2-bytes
- keccak_truncated_bits: 21 x 8-bytes

#### Flushing rules

- push (msg_digest | nonce | padding, derived_digest | keccak_truncated_bits) into the keccak-f-channel
- pull (derived_digest, signature_index) from the derived-message-digest-channel
- push (msg_digest, signature_index) into the message-digest-channel


## Channels

### The keccak-f-channel

(A 200-byte perm_input, A 200-byte perm_output)
200-byte is represented by 25 x columns of 8-byte

### The merkle-channel

(4 x 8-byte, 8-byte, 1-byte) = (hash, signature_index, xmss_depth)

### The message-digest-channel

(4 x 8-byte, 8-byte) = (message_digest, signature_index)

### The derived-message-digest-channel

(4 x 8-byte, 8-byte) = (derived_message_digest, signature_index)

### The hash-chain-counter-channel

(4 x 8-byte, 8-byte, 2-byte, 1-bytes) = (hash, signature_index, chain_length, wots_chunk_index)

### The lookup-channel

(2-byte, 2-byte, 64-byte) =  (chain_length_mul, chain_length_add, timestamp)        (generator16^X, 2^W - 1 - X, timestamp)

## Boundary conditions

- For each signer s at index i, pull (pub_key(s), i, 1) from the merkle-channel
- For each message m at index i, pull (digest(m), i) from the message-digest-channel
