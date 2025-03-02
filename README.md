# Conservative XMSS Signature Aggregation

## TLDR

Benchmark for aggregating keccak based XMSS signatures using Binius.

## Introduction

XMSS is a stateful signature scheme based on hash functions. Its quantum-resistant properties make it a promising candidate for future Ethereum Beacon Chain signatures ([ref](https://eprint.iacr.org/2025/055.pdf)).

The underlying hash function presents two main options:
- conservative: keccak256 / sha3
- zk-friendly / modern: poseidon2

The end goal is efficient aggregation of thousands of signatures into a concise proof.

Binius, a proof system developed by [Irreductible](https://www.irreducible.com/), leverages binary fields to substantially reduce the keccak-f arithmetization overhead ([first paper](https://eprint.iacr.org/2023/1784.pdf), [second paper](https://eprint.iacr.org/2024/504.pdf)).

This repository implements the conservative approach using XMSS signatures with keccak256. It provides an arithmetization of XMSS signature verification, allowing a prover to efficiently aggregate multiple XMSS signatures into a single proof using Binius. This project serves as a prototype for benchmarking purposes and is not production-ready.

For detailed cryptographic and arithmetization information, refer to DETAILS.md.

## Running benchmarks

Verify GFNI (Galois Field New Instructions) support on your system for optimal performance:

```bash
rustc --print cfg -C target-cpu=native | grep gfni
```

Then execute:

```rust
RUSTFLAGS="-C target-cpu=native" cargo run --release
```

## Results

On the machine where tests were performed, proving 8192 keccak-f permutations requires approximately 3 seconds, aligning with [Irreductible's benchmarks](https://www.binius.xyz/benchmarks/).

Using WOTS chunks of 2 bits (W in the code), verification of 256 XMSS signatures requires 61K keccak-f permutations, suggesting an expected aggregation time of 22s. However, when including all XMSS constraints, the actual duration extends to 2 minutes, indicating that the supplementary logic around keccak-f proof carries a 6x overhead. Additional optimization is required to reduce it.

The proof is slightly less than 1 mega, but there is hope that this will be reduced in the future.

Performance improvements are anticipated through both arithmetization enhancements and future updates to the Binius library (potentially including GPU/FPGA support).

## License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)




