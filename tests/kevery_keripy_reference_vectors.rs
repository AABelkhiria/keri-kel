//! Message sequences processed by the pinned keripy reference, replayed through the port.
//!
//! Each scenario offers keripy's `Kevery` a sequence of events and receipts, processing escrows
//! after each, and records the outcome of every message and everything keripy held afterwards. The
//! port must reach the same outcomes and hold the same key states, the same stored signatures for
//! every accepted event, and the same number of events and receipts waiting. See
//! `fixtures/kevery-keripy/README.md`.

use std::error::Error;

use keri_cesr::crypto::signature::IndexedSignature;
use keri_kel::{Escrow, KelError, Kevery, Processed};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::stream::Message;
use serde::Deserialize;

const REFERENCE_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";

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
    divergence_attached_witness_couple: Divergence,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    note: String,
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
struct Divergence {
    name: String,
    note: String,
    steps: Vec<Step>,
    promoted_witness: String,
}

#[derive(Debug, Deserialize)]
struct Step {
    label: String,
    raw: String,
    raw_hex: String,
    rust_outcome: String,
    keripy: Raised,
    after: Snapshot,
}

#[derive(Debug, Deserialize)]
struct Raised {
    raised: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Snapshot {
    states: Vec<IdentifierSnapshot>,
    escrowed_events: usize,
    waiting_receipts: usize,
}

#[derive(Debug, Deserialize)]
struct IdentifierSnapshot {
    identifier: String,
    state_json: Option<String>,
    events: Vec<EventSnapshot>,
}

#[derive(Debug, Deserialize)]
struct EventSnapshot {
    sequence_number: u128,
    said: String,
    signatures: Vec<String>,
    witness_signatures: Vec<String>,
    receipts: Vec<String>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/kevery-keripy/v1.json"
    )))?)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !input.len().is_multiple_of(2) {
        return Err("odd-length hexadecimal fixture field".into());
    }
    (0..input.len())
        .step_by(2)
        .map(|index| {
            input
                .get(index..index + 2)
                .ok_or_else(|| Box::<dyn Error>::from("hexadecimal fixture slice out of range"))
                .and_then(|pair| u8::from_str_radix(pair, 16).map_err(Into::into))
        })
        .collect()
}

fn outcome_matches(result: &Result<Processed, KelError>, expected: &str) -> bool {
    match expected {
        "Accepted" => matches!(result, Ok(Processed::Accepted)),
        "Duplicate" => matches!(result, Ok(Processed::Duplicate)),
        "Receipted" => matches!(result, Ok(Processed::Receipted)),
        "Escrowed:PartiallySigned" => matches!(result, Ok(Processed::Escrowed(Escrow::PartiallySigned))),
        "Escrowed:PartiallyWitnessed" => matches!(result, Ok(Processed::Escrowed(Escrow::PartiallyWitnessed))),
        "Escrowed:UnverifiedReceipt" => matches!(result, Ok(Processed::Escrowed(Escrow::UnverifiedReceipt))),
        "StaleReceipt" => matches!(result, Err(KelError::StaleReceipt)),
        "LikelyDuplicitous" => matches!(result, Err(KelError::LikelyDuplicitous)),
        _ => false,
    }
}

/// What the port holds for one identifier, in the fixture's vocabulary.
fn held(kevery: &Kevery, identifier: &str) -> Result<(Option<String>, Vec<EventSnapshot>), Box<dyn Error>> {
    let prefix = IdentifierPrefix::from_qb64(identifier)?;
    let Some(kever) = kevery.kever(&prefix) else {
        return Ok((None, Vec::new()));
    };
    let state = String::from_utf8(kever.state()?.to_sad()?.to_json_bytes()?)?;
    let mut events = Vec::new();
    for sequence_number in 0..=kever.sequence_number() {
        let Some(logged) = kevery.logged(&prefix, sequence_number) else {
            continue;
        };
        let mut signatures: Vec<String> = logged
            .signatures()
            .iter()
            .map(IndexedSignature::qb64)
            .collect::<Result<_, _>>()?;
        let mut witness_signatures: Vec<String> = logged
            .witness_signatures()
            .iter()
            .map(IndexedSignature::qb64)
            .collect::<Result<_, _>>()?;
        let mut receipts: Vec<String> = logged
            .receipts()
            .iter()
            .map(|couple| -> Result<String, Box<dyn Error>> {
                Ok(format!("{}{}", couple.verifier().qb64()?, couple.signature().qb64()?))
            })
            .collect::<Result<_, _>>()?;
        signatures.sort();
        witness_signatures.sort();
        receipts.sort();
        events.push(EventSnapshot {
            sequence_number,
            said: logged.event().said().unwrap_or_default().to_owned(),
            signatures,
            witness_signatures,
            receipts,
        });
    }
    Ok((Some(state), events))
}

fn compare(kevery: &Kevery, expected: &Snapshot, context: &str) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        kevery.escrowed_events(),
        expected.escrowed_events,
        "{context}: escrowed events"
    );
    assert_eq!(
        kevery.waiting_receipts(),
        expected.waiting_receipts,
        "{context}: waiting receipts"
    );
    for identifier in &expected.states {
        let (state, events) = held(kevery, &identifier.identifier)?;
        assert_eq!(state, identifier.state_json, "{context}: key state");
        assert_eq!(events.len(), identifier.events.len(), "{context}: accepted events");
        for (ours, theirs) in events.iter().zip(&identifier.events) {
            let at = format!("{context} at {}", theirs.sequence_number);
            assert_eq!(ours.sequence_number, theirs.sequence_number, "{at}");
            assert_eq!(ours.said, theirs.said, "{at}: said");
            assert_eq!(ours.signatures, theirs.signatures, "{at}: signatures");
            assert_eq!(
                ours.witness_signatures, theirs.witness_signatures,
                "{at}: witness signatures"
            );
            assert_eq!(ours.receipts, theirs.receipts, "{at}: receipts");
        }
    }
    Ok(())
}

fn offer(kevery: &mut Kevery, step: &Step, now: &Timestamp) -> Result<Result<Processed, KelError>, Box<dyn Error>> {
    let raw = decode_hex(&step.raw_hex)?;
    assert_eq!(raw, step.raw.as_bytes(), "step {} raw and raw_hex disagree", step.label);
    let message = Message::from_bytes(&raw)?;
    let result = kevery.process(&message, now);
    kevery.process_escrows(now);
    Ok(result)
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
    assert_eq!(fixture.scenarios.len(), 4);
    let mut steps = 0;
    for scenario in &fixture.scenarios {
        assert_ne!(scenario.note, "");
        let mut kevery = Kevery::new();
        for step in &scenario.steps {
            steps += 1;
            let context = format!("{}/{}", scenario.name, step.label);
            let result = offer(&mut kevery, step, &now)?;
            assert!(
                outcome_matches(&result, &step.rust_outcome),
                "{context}: expected {}, got {result:?} (keripy raised {:?}: {:?})",
                step.rust_outcome,
                step.keripy.raised,
                step.keripy.message
            );
            compare(&kevery, &step.after, &context)?;
        }
    }
    assert_eq!(steps, 15);
    Ok(())
}

#[test]
fn an_attached_witness_couple_counts_as_the_witness_signature() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let divergence = &fixture.divergence_attached_witness_couple;
    assert_eq!(divergence.name, "attached_witness_couple");
    assert_ne!(divergence.note, "");
    let step = divergence.steps.first().ok_or("divergence has no steps")?;
    let mut kevery = Kevery::new();
    let result = offer(&mut kevery, step, &now)?;
    assert!(outcome_matches(&result, &step.rust_outcome), "got {result:?}");

    let keripy = step.after.states.first().ok_or("no state")?;
    let keripy_event = keripy.events.first().ok_or("no event")?;
    assert_eq!(
        keripy_event.witness_signatures.len(),
        1,
        "keripy counts one witness signature"
    );
    assert_eq!(keripy_event.receipts.len(), 1, "keripy keeps the couple as a receipt");
    assert!(
        keripy_event
            .receipts
            .iter()
            .all(|receipt| receipt.starts_with(&divergence.promoted_witness))
    );

    let (_, events) = held(&kevery, &keripy.identifier)?;
    let ours = events.first().ok_or("the port holds no event")?;
    assert_eq!(ours.witness_signatures.len(), 2, "the port counts both witnesses");
    assert!(
        ours.receipts.is_empty(),
        "the port keeps no plain receipt for a witness"
    );
    for signature in &keripy_event.witness_signatures {
        assert!(ours.witness_signatures.contains(signature));
    }
    assert_eq!(ours.signatures, keripy_event.signatures);
    Ok(())
}

#[test]
fn escrowed_items_expire_before_a_cutoff() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let scenario = fixture
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "signatures_gathered_across_offers")
        .ok_or("no scenario")?;
    let step = scenario.steps.first().ok_or("no step")?;
    let mut kevery = Kevery::new();
    offer(&mut kevery, step, &now)??;
    assert_eq!(kevery.escrowed_events(), 1);
    assert_eq!(kevery.expire_escrows(&now), 0, "nothing escrowed at the cutoff expires");
    assert_eq!(
        kevery.expire_escrows(&Timestamp::parse("2021-01-01T00:00:00.000001+00:00")?),
        1
    );
    assert_eq!(kevery.escrowed_events(), 0);
    Ok(())
}
