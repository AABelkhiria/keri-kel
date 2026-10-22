//! Delegated identifiers processed by the pinned keripy reference, replayed through the port.
//!
//! Each scenario offers keripy's `Kevery` a delegator's and a delegate's events in some order,
//! processing escrows after each, and records the outcome of every message and everything keripy
//! held afterwards, including the delegating event stored with each delegated event. The port must
//! reach the same outcomes and hold the same. See `fixtures/delegation-keripy/README.md`.

mod support;

use std::error::Error;

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_cesr::sequence::SequenceNumber;
use keri_kel::{Escrow, KelError, Kever, Kevery, Processed};
use keri_protocol::attachment::{AttachmentFraming, SealSourceCouple, SignedMessageBuilder};
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::PrefixDerivation;
use keri_protocol::serialization::Sad;
use keri_protocol::stream::Message;
use serde::Deserialize;
use support::{REFERENCE_SHA, Scenario, decode_hex, replay};

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    reference_version: String,
    generated_on: String,
    sources: Vec<String>,
    now: String,
    scenarios: Vec<Scenario>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/delegation-keripy/v1.json"
    )))?)
}

fn scenario<'a>(fixture: &'a Fixture, name: &str) -> Result<&'a Scenario, Box<dyn Error>> {
    Ok(fixture
        .scenarios
        .iter()
        .find(|scenario| scenario.name == name)
        .ok_or("no such scenario")?)
}

fn message(scenario: &Scenario, label: &str) -> Result<Message, Box<dyn Error>> {
    let step = scenario
        .steps
        .iter()
        .find(|step| step.label == label)
        .ok_or("no such step")?;
    Ok(Message::from_bytes(&decode_hex(&step.raw_hex)?)?)
}

#[test]
fn fixture_metadata_matches_the_pinned_keripy_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/keripy.git");
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.reference_version, "1.3.6");
    assert_ne!(fixture.generated_on, "");
    assert_eq!(fixture.sources, ["src/keri/core/eventing.py"]);
    Timestamp::parse(&fixture.now)?;
    Ok(())
}

#[test]
fn every_scenario_holds_what_keripy_holds() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    assert_eq!(fixture.scenarios.len(), 7);
    assert_eq!(replay(&fixture.scenarios, &now)?, 27);
    Ok(())
}

/// A `Kever` on its own holds no delegator's log, so it cannot approve a delegated inception.
#[test]
fn a_lone_kever_cannot_approve_a_delegation() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let anchored = scenario(&fixture, "anchored_delegation")?;
    let error = Kever::incept(&message(anchored, "delegated_inception")?, now)
        .err()
        .ok_or("a lone kever accepted a delegated inception")?;
    assert!(matches!(error, KelError::DelegatorUnknown));
    assert_eq!(error.escrow(), Some(Escrow::PartiallyDelegated));
    Ok(())
}

/// A delegated event that names its delegating event is accepted the moment the anchor is there,
/// without waiting for an escrow pass.
#[test]
fn a_named_anchor_is_found_without_an_escrow_pass() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let anchored = scenario(&fixture, "anchored_delegation")?;
    let mut kevery = Kevery::new();
    for label in [
        "delegator_inception",
        "delegator_anchors_the_inception",
        "delegated_inception",
    ] {
        assert_eq!(
            kevery.process(&message(anchored, label)?, &now)?,
            Processed::Accepted,
            "{label}"
        );
    }
    Ok(())
}

/// Without a named anchor, only an escrow pass looks through the delegator's log.
#[test]
fn an_unnamed_anchor_is_found_by_the_escrow_pass() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let waiting = scenario(&fixture, "delegation_waits_for_its_anchor")?;
    let mut kevery = Kevery::new();
    kevery.process(&message(waiting, "delegator_inception")?, &now)?;
    kevery.process(&message(waiting, "delegator_anchors_the_inception")?, &now)?;
    assert_eq!(
        kevery.process(&message(waiting, "delegated_inception_without_source")?, &now)?,
        Processed::Escrowed(Escrow::PartiallyDelegated)
    );
    assert_eq!(kevery.process_escrows(&now), 1);
    assert_eq!(kevery.escrowed_events(), 0);
    Ok(())
}

fn signed(event: &KeyEvent, signer: &Signer, source: Option<SealSourceCouple>) -> Result<Message, Box<dyn Error>> {
    let signature = signer.sign_indexed(event.raw(), SignaturePlacement::both_lists(0))?;
    let mut bytes = SignedMessageBuilder::new(event.serialized())
        .controller_signatures(vec![signature])
        .build()?
        .into_bytes();
    if let Some(source) = source {
        bytes.extend(source.attachment(AttachmentFraming::Plain)?);
    }
    Ok(Message::from_bytes(&bytes)?)
}

fn inception(signer: &Signer, next: &Signer) -> InceptionBuilder {
    InceptionBuilder::new(vec![signer.verifier().clone()])
        .next_key_digests(vec![Digest::derive(
            DigestAlgorithm::Blake3_256,
            &next.verifier().qb64_bytes().unwrap_or_default(),
        )])
        .prefix_derivation(PrefixDerivation::Blake3_256)
}

/// keripy recognises an event seal only when its fields are exactly `i`, `s` and `d`, in that
/// order: the same fields in another order do not anchor.
#[test]
fn a_seal_with_its_fields_reordered_does_not_anchor() -> Result<(), Box<dyn Error>> {
    let now = Timestamp::parse("2021-01-01T00:00:00.000000+00:00")?;
    let signer = |seed: u8| Signer::from_seed(&[seed; 32], KeyTransferability::Transferable);
    let (boss, boss_next, delegate, delegate_next) = (signer(1)?, signer(2)?, signer(3)?, signer(4)?);
    let delegator = inception(&boss, &boss_next).build()?;
    let delegated = inception(&delegate, &delegate_next)
        .delegator(delegator.identifier().clone())
        .build()?;
    let mut reordered = Sad::new();
    reordered.insert("s", "0")?;
    reordered.insert("i", delegated.identifier().qb64()?)?;
    reordered.insert("d", delegated.said().qb64()?)?;
    let anchor = InteractionBuilder::new(delegator.identifier().clone(), delegator.said(), 1)
        .anchors(vec![reordered])
        .build()?;

    let mut kevery = Kevery::new();
    assert_eq!(
        kevery.process(&signed(&delegator, &boss, None)?, &now)?,
        Processed::Accepted
    );
    assert_eq!(
        kevery.process(&signed(&anchor, &boss, None)?, &now)?,
        Processed::Accepted
    );
    let source = SealSourceCouple::new(SequenceNumber::new(1), anchor.said());
    assert_eq!(
        kevery.process(&signed(&delegated, &delegate, Some(source))?, &now)?,
        Processed::Escrowed(Escrow::PartiallyDelegated)
    );
    assert_eq!(kevery.process_escrows(&now), 0);
    assert!(kevery.kever(delegated.identifier()).is_none());

    // The same fields in keripy's order, anchored next, approve it.
    let mut ordered = Sad::new();
    ordered.insert("i", delegated.identifier().qb64()?)?;
    ordered.insert("s", "0")?;
    ordered.insert("d", delegated.said().qb64()?)?;
    let reanchor = InteractionBuilder::new(delegator.identifier().clone(), anchor.said(), 2)
        .anchors(vec![ordered])
        .build()?;
    assert_eq!(
        kevery.process(&signed(&reanchor, &boss, None)?, &now)?,
        Processed::Accepted
    );
    assert_eq!(kevery.process_escrows(&now), 1);
    let logged = kevery
        .logged(delegated.identifier(), 0)
        .ok_or("the delegate was not accepted")?;
    let delegation = logged.delegation().ok_or("no delegating event stored")?;
    assert_eq!(delegation.sequence_number().value(), 2);
    assert_eq!(delegation.said(), reanchor.said());
    Ok(())
}
