//! Recovery rotations processed by the pinned keripy reference, replayed through the port.
//!
//! Each scenario offers keripy's `Kevery` a log and a rotation recovering it, processing escrows
//! after each, and records the outcome of every message and everything keripy held afterwards,
//! superseded events included. The port must reach the same outcomes and hold the same. See
//! `fixtures/recovery-keripy/README.md`.

mod support;

use std::error::Error;

use keri_kel::{Kevery, Processed};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
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
        "/fixtures/recovery-keripy/v1.json"
    )))?)
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
    assert_eq!(fixture.scenarios.len(), 5);
    assert_eq!(replay(&fixture.scenarios, &now, |kevery| kevery)?, 21);
    Ok(())
}

/// The events a recovery supersedes are the ones from its sequence number on, kept in order, and
/// the log reads as if they had never been accepted.
#[test]
fn a_recovery_keeps_what_it_supersedes_in_order() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let scenario = fixture
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "recovery_supersedes_interactions")
        .ok_or("no such scenario")?;
    let mut kevery = Kevery::new();
    let mut offered = Vec::new();
    for step in scenario.steps.iter().take(5) {
        let message = Message::from_bytes(&decode_hex(&step.raw_hex)?)?;
        assert_eq!(kevery.process(&message, &now)?, Processed::Accepted, "{}", step.label);
        offered.push(message);
    }
    let identifier = IdentifierPrefix::from_qb64(
        offered
            .first()
            .and_then(|message| message.event().identifier_prefix())
            .ok_or("no identifier")?,
    )?;
    let superseded = kevery.superseded(&identifier)?;
    let superseded: Vec<Option<&str>> = superseded.iter().map(|logged| logged.event().said()).collect();
    let expected: Vec<Option<&str>> = offered
        .get(2..4)
        .ok_or("too few messages")?
        .iter()
        .map(|message| message.event().said())
        .collect();
    assert_eq!(superseded, expected, "the second and third interactions, in order");
    let kever = kevery.kever(&identifier)?.ok_or("no key state")?;
    assert_eq!(kever.sequence_number(), 2);
    assert!(kevery.logged(&identifier, 3)?.is_none());
    Ok(())
}
