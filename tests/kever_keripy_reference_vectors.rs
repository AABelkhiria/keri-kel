//! Key event logs validated by the pinned keripy reference, replayed through the port.
//!
//! Every scenario offers keripy's `Kever` a sequence of signed events and records what it did with
//! each. The port must accept the same events into the same key state, and refuse the others with
//! the error category each step names, leaving the state unchanged. See
//! `fixtures/kever-keripy/README.md`.

use std::error::Error;

use keri_kel::{Escrow, KelError, Kever};
use keri_protocol::event::timestamp::Timestamp;
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
    first_seen: String,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    note: String,
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
struct Step {
    label: String,
    raw: String,
    raw_hex: String,
    rust_error_category: Option<String>,
    keripy: Outcome,
}

#[derive(Debug, Deserialize)]
struct Outcome {
    accepted: bool,
    #[serde(default)]
    state_json: Option<String>,
    #[serde(default)]
    error_category: Option<String>,
    #[serde(default)]
    error_message: Option<String>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/kever-keripy/v1.json"
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

fn category_matches(error: &KelError, category: &str) -> Result<bool, Box<dyn Error>> {
    Ok(match category {
        "PriorMismatch" => matches!(error, KelError::PriorMismatch),
        "OutOfOrder" => matches!(error, KelError::OutOfOrder { .. }),
        "Stale" => matches!(error, KelError::Stale { .. }),
        "NoVerifiedSignatures" => matches!(error, KelError::NoVerifiedSignatures),
        "NotFullySigned" => matches!(error, KelError::NotFullySigned),
        "PriorNextNotSatisfied" => matches!(error, KelError::PriorNextNotSatisfied),
        "NotFullyWitnessed" => matches!(error, KelError::NotFullyWitnessed),
        "IdentifierMismatch" => matches!(error, KelError::IdentifierMismatch),
        "CutNotAWitness" => matches!(error, KelError::CutNotAWitness),
        "ConflictingWitnessLists" => matches!(error, KelError::ConflictingWitnessLists { .. }),
        "InvalidWitnessThreshold" => matches!(error, KelError::InvalidWitnessThreshold { .. }),
        "EstablishmentOnly" => matches!(error, KelError::EstablishmentOnly),
        "NotTransferable" => matches!(error, KelError::NotTransferable),
        "ThresholdExceedsKeys" => matches!(error, KelError::ThresholdExceedsKeys { .. }),
        "DuplicateWitness" => matches!(error, KelError::DuplicateWitness { .. }),
        "NonZeroInception" => matches!(error, KelError::NonZeroInception),
        other => return Err(format!("unknown rust error category {other}").into()),
    })
}

/// Offers one step to the port: an inception when there is no log yet, an update otherwise.
fn offer(
    kever: &mut Option<Kever>,
    step: &Step,
    first_seen: &Timestamp,
) -> Result<Result<(), KelError>, Box<dyn Error>> {
    let raw = decode_hex(&step.raw_hex)?;
    assert_eq!(raw, step.raw.as_bytes(), "step {} raw and raw_hex disagree", step.label);
    let message = Message::from_bytes(&raw)?;
    Ok(match kever {
        None => Kever::incept(&message, first_seen.clone()).map(|started| {
            *kever = Some(started);
        }),
        Some(existing) => existing.update(&message, first_seen.clone()),
    })
}

fn state_json(kever: Option<&Kever>) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    kever
        .map(|kever| -> Result<Vec<u8>, Box<dyn Error>> { Ok(kever.state()?.to_sad()?.to_json_bytes()?) })
        .transpose()
}

#[test]
fn fixture_metadata_matches_the_pinned_keripy_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/keripy.git");
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.reference_version, "1.3.6");
    assert_ne!(fixture.generated_on, "");
    assert_eq!(
        fixture.sources,
        ["src/keri/core/eventing.py", "src/keri/core/serdering.py"]
    );
    Timestamp::parse(&fixture.first_seen)?;
    Ok(())
}

#[test]
fn every_scenario_ends_where_keripy_ends() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let first_seen = Timestamp::parse(&fixture.first_seen)?;
    assert_eq!(fixture.scenarios.len(), 14);
    let mut steps = 0;
    for scenario in &fixture.scenarios {
        assert_ne!(scenario.note, "");
        let mut kever = None;
        for step in &scenario.steps {
            steps += 1;
            let before = state_json(kever.as_ref())?;
            let result = offer(&mut kever, step, &first_seen)?;
            let context = format!("{}/{}", scenario.name, step.label);
            match (&step.rust_error_category, result) {
                (None, Ok(())) => {
                    assert!(step.keripy.accepted, "{context}: the port accepted what keripy refused");
                    let expected = step.keripy.state_json.as_deref().ok_or("accepted step has no state")?;
                    let actual = state_json(kever.as_ref())?.ok_or("no state after an accepted step")?;
                    assert_eq!(
                        String::from_utf8(actual)?,
                        expected,
                        "{context}: the port's key state differs from keripy's"
                    );
                }
                (Some(category), Err(error)) => {
                    assert!(
                        !step.keripy.accepted,
                        "{context}: the port refused what keripy accepted"
                    );
                    assert!(step.keripy.error_category.is_some() && step.keripy.error_message.is_some());
                    assert!(category_matches(&error, category)?, "{context}: produced {error:?}");
                    assert_eq!(
                        state_json(kever.as_ref())?,
                        before,
                        "{context}: a refused event changed the state"
                    );
                }
                (None, Err(error)) => return Err(format!("{context}: the port refused with {error}").into()),
                (Some(category), Ok(())) => {
                    return Err(format!("{context}: the port accepted, expected {category}").into());
                }
            }
        }
    }
    assert_eq!(steps, 41);
    Ok(())
}

#[test]
fn signature_and_witness_shortfalls_are_escrowable() {
    assert_eq!(KelError::NotFullySigned.escrow(), Some(Escrow::PartiallySigned));
    assert_eq!(KelError::PriorNextNotSatisfied.escrow(), Some(Escrow::PartiallySigned));
    assert_eq!(KelError::NotFullyWitnessed.escrow(), Some(Escrow::PartiallyWitnessed));
    assert_eq!(KelError::PriorMismatch.escrow(), None);
    assert_eq!(KelError::NoVerifiedSignatures.escrow(), None);
}
