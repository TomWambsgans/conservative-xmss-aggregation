#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use std::time::Instant;

use arithmetization::{tables::keccakf::KeccakfInfo, Arithmetization};
use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
    constraint_system::Proof, fiat_shamir::HasherChallenger, tower::CanonicalTowerFamily,
};
use binius_field::arch::OptimalUnderlier;
use binius_hal::make_portable_backend;
use binius_hash::compress::Groestl256ByteCompression;
use binius_math::IsomorphicEvaluationDomainFactory;
use bytesize::ByteSize;
use config::*;
use itertools::Itertools;
use utils::*;
use xmss::*;

mod arithmetization;
mod config;
mod utils;
mod wots;
mod xmss;

fn main() {
    println!("XMSS Aggregation Benchmark\n");
    println!("- Hash function: Keccak256");
    println!(
        "- XMSS height: {} ({} signatures per key)",
        XMSS_HEIGHT,
        1 << XMSS_HEIGHT
    );
    println!("- W (bits per WOTS chunk): {}", W);
    println!(
        "- Size of XMSS signature: {}",
        ByteSize::b(32 * (N_WOTS_CHUNKS + XMSS_HEIGHT) as u64)
    );
    println!(
        "- Binius settings: SECURITY_BITS = {}, LOG_INVERSE_RATE = {}",
        SECURITY_BITS, LOG_INVERSE_RATE
    );

    for aggregation_count in [16, 32, 64, 128, 256] {
        println!("\n{}\n", "-".repeat(80));
        println!("Aggregation of {} XMSS signatures:\n", aggregation_count);

        let instant = Instant::now();
        let (public_keys, msg_digests, signatures) =
            generate_random_xmss_signatures(aggregation_count);
        println!(
            "XMSS keys generated in: {}",
            format_duration(instant.elapsed())
        );

        let instant = Instant::now();
        let aggregated_signature =
            aggregate_xmss_signatures(&public_keys, &msg_digests, &signatures);
        println!(
            "Aggregation took: {} ({} keccakf permutations)",
            format_duration(instant.elapsed()),
            aggregated_signature.total_keccakf_count
        );
        println!(
            "Aggregated signature size: {}",
            ByteSize::b(aggregated_signature.proof.get_proof_size() as u64)
        );

        let instant = Instant::now();
        verify_xmss_aggregated_siganture(&public_keys, &msg_digests, aggregated_signature).unwrap();
        println!("Verification took: {}", format_duration(instant.elapsed()));
    }
}

#[derive(Clone)]
pub struct AggregatedXmssSignature {
    pub total_keccakf_count: usize,
    pub proof: Proof,
}

/// Signatures must be verified before aggregation.
pub fn aggregate_xmss_signatures(
    public_keys: &[XmssPublicKey],
    msg_digests: &[Hash],
    signatures: &[XmssSignature],
) -> AggregatedXmssSignature {
    assert!(public_keys.len() == msg_digests.len() && msg_digests.len() == signatures.len());

    let xmss_witnesses = public_keys
        .iter()
        .zip(msg_digests)
        .zip(signatures)
        .map(|((pub_key, msg_digest), signature)| {
            signature
                .verify_with_witness(pub_key, msg_digest)
                .expect("Signature should have been verified before aggregation")
        })
        .collect::<Vec<_>>();

    let all_keccakf_states = xmss_witnesses
        .iter()
        .map(|w| w.all_keccakf_states.clone())
        .concat();
    let total_keccakf_count = all_keccakf_states.len();

    let backend = make_portable_backend();
    let allocator = bumpalo::Bump::new();
    let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);
    let arithmetization = Arithmetization::build(
        &mut builder,
        signatures.len(),
        &public_keys,
        &msg_digests,
        KeccakfInfo::ProverMode(all_keccakf_states),
    );

    arithmetization
        .tables
        .fill(builder.witness().unwrap(), &xmss_witnesses);

    let witness = builder.take_witness().unwrap();
    let constraint_system = builder.build().unwrap();
    let domain_factory = IsomorphicEvaluationDomainFactory::<B8>::default();
    let proof = binius_core::constraint_system::prove::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        _,
        groestl_crypto::Groestl256,
        Groestl256ByteCompression,
        HasherChallenger<groestl_crypto::Groestl256>,
        _,
    >(
        &constraint_system,
        LOG_INVERSE_RATE,
        SECURITY_BITS,
        &arithmetization.boundaries,
        witness,
        &domain_factory,
        &backend,
    )
    .unwrap();

    AggregatedXmssSignature {
        total_keccakf_count,
        proof,
    }
}

fn verify_xmss_aggregated_siganture(
    public_keys: &[XmssPublicKey],
    msg_digests: &[Hash],
    aggregated_signature: AggregatedXmssSignature,
) -> Result<(), binius_core::constraint_system::error::Error> {
    assert_eq!(public_keys.len(), msg_digests.len());
    assert!(public_keys.len() <= MAX_AGGREGATED_SIGNATURES);
    let aggregation_count = public_keys.len();

    let mut builder = ConstraintSystemBuilder::new();

    let arithmetization = Arithmetization::build(
        &mut builder,
        aggregation_count,
        &public_keys,
        &msg_digests,
        KeccakfInfo::VerifierMode {
            total_keccakf_count: aggregated_signature.total_keccakf_count,
        },
    );

    let constraint_system = builder.build().unwrap();

    binius_core::constraint_system::verify::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        groestl_crypto::Groestl256,
        Groestl256ByteCompression,
        HasherChallenger<groestl_crypto::Groestl256>,
    >(
        &constraint_system,
        LOG_INVERSE_RATE,
        SECURITY_BITS,
        &arithmetization.boundaries,
        aggregated_signature.proof,
    )
}
