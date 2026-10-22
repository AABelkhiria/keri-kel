//! Microbenchmarks for key event validation.
//!
//! A watcher validates every event it fetches from a witness. The measured log is one identifier's
//! inception followed by alternating interactions and rotations, each signed by one key, so the
//! numbers are one signature verification plus one SAID recomputation per event, and one digest
//! comparison per rotation.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_kel::Kever;
use keri_protocol::attachment::SignedMessageBuilder;
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::rotation::RotationBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::PrefixDerivation;
use keri_protocol::stream::Message;

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";
const EVENTS: u8 = 32;

fn signed(event: &KeyEvent, signer: &Signer) -> Option<Message> {
    let signature = signer
        .sign_indexed(event.raw(), SignaturePlacement::both_lists(0))
        .ok()?;
    let bytes = SignedMessageBuilder::new(event.serialized())
        .controller_signatures(vec![signature])
        .build()
        .ok()?;
    Message::from_bytes(bytes.as_bytes()).ok()
}

fn commitment(signer: &Signer) -> Option<Digest> {
    Some(Digest::derive(
        DigestAlgorithm::Blake3_256,
        &signer.verifier().qb64_bytes().ok()?,
    ))
}

/// One inception and `EVENTS` more events, alternating interaction and rotation.
fn log() -> Option<Vec<Message>> {
    let signers: Vec<Signer> = (0..=EVENTS)
        .map(|seed| Signer::from_seed(&[seed.wrapping_add(1); 32], KeyTransferability::Transferable).ok())
        .collect::<Option<_>>()?;
    let mut keys = signers.iter();
    let mut current = keys.next()?;
    let mut next = keys.next()?;
    let inception = InceptionBuilder::new(vec![current.verifier().clone()])
        .next_key_digests(vec![commitment(next)?])
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()
        .ok()?;
    let identifier = inception.identifier().clone();
    let mut prior = inception.said();
    let mut messages = vec![signed(&inception, current)?];
    for sequence_number in 1..=u128::from(EVENTS) {
        let event = if sequence_number.is_multiple_of(2) {
            let after = keys.next()?;
            let event = RotationBuilder::new(
                identifier.clone(),
                prior,
                sequence_number,
                vec![next.verifier().clone()],
            )
            .next_key_digests(vec![commitment(after)?])
            .build()
            .ok()?;
            current = next;
            next = after;
            event
        } else {
            InteractionBuilder::new(identifier.clone(), prior, sequence_number)
                .build()
                .ok()?
        };
        messages.push(signed(&event, current)?);
        prior = event.said();
    }
    Some(messages)
}

fn benchmark_kever(criterion: &mut Criterion) {
    let (Some(messages), Ok(stamp)) = (log(), Timestamp::parse(STAMP)) else {
        return;
    };
    let Some((inception, rest)) = messages.split_first() else {
        return;
    };
    criterion.bench_function("validate_log_of_33_events", |bencher| {
        bencher.iter(|| {
            let mut kever = Kever::incept(black_box(inception), stamp.clone()).ok()?;
            for message in rest {
                kever.update(black_box(message), stamp.clone()).ok()?;
            }
            Some(kever.sequence_number())
        });
    });
}

criterion_group!(benches, benchmark_kever);
criterion_main!(benches);
