//! Delegated rotations superseding accepted events, processed by the pinned keripy reference and
//! replayed through the port.
//!
//! Each scenario offers keripy's `Kevery` a delegator's and a delegate's events, processing escrows
//! after each, and records the outcome of every message and everything keripy held afterwards,
//! superseded events included. The port must reach the same outcomes and hold the same. See
//! `fixtures/delegated-recovery-keripy/README.md`.

mod support;

use std::error::Error;

use keri_kel::{Escrow, KelError, Kevery, Processed};
use keri_protocol::event::timestamp::Timestamp;
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
        "/fixtures/delegated-recovery-keripy/v1.json"
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
    assert_eq!(fixture.scenarios.len(), 6);
    assert_eq!(replay(&fixture.scenarios, &now)?, 42);
    Ok(())
}

/// keripy waits before refusing a delegated rotation that would supersede an earlier interaction:
/// only a retry searches the delegator's log for the latest event's delegating event, finds none,
/// and drops the rotation.
#[test]
fn an_earlier_interaction_is_refused_only_on_retry() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let scenario = fixture
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "earlier_interaction_is_not_superseded")
        .ok_or("no such scenario")?;
    let (last, earlier) = scenario.steps.split_last().ok_or("no steps")?;
    let mut kevery = Kevery::new();
    for step in earlier {
        kevery.process(&Message::from_bytes(&decode_hex(&step.raw_hex)?)?, &now)?;
    }
    let message = Message::from_bytes(&decode_hex(&last.raw_hex)?)?;
    assert_eq!(
        kevery.process(&message, &now)?,
        Processed::Escrowed(Escrow::PartiallyDelegated)
    );
    assert_eq!(kevery.escrowed_events(), 1);
    assert_eq!(kevery.process_escrows(&now), 0);
    assert_eq!(kevery.escrowed_events(), 0, "the retry drops it");
    assert!(KelError::SupersededWithoutDelegation.escrow().is_none());
    Ok(())
}
