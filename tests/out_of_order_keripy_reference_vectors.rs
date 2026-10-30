//! Out-of-order and likely-duplicitous events processed by the pinned keripy reference, replayed
//! through the port.
//!
//! Each scenario offers keripy's `Kevery` events before the ones they follow, or contradicting ones
//! already accepted, processing escrows after each, and records the outcome of every message and
//! everything keripy held afterwards. The port must reach the same outcomes and hold the same. See
//! `fixtures/out-of-order-keripy/README.md`.

mod support;

use std::error::Error;

use keri_kel::{Escrow, Kevery, Processed};
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
        "/fixtures/out-of-order-keripy/v1.json"
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
    assert_eq!(replay(&fixture.scenarios, &now, |kevery| kevery)?, 25);
    Ok(())
}

/// A log offered backwards is accepted whole by one escrow pass after its inception: the pass
/// retries the waiting events in sequence order, whatever order they arrived in.
#[test]
fn one_pass_accepts_a_log_offered_backwards() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let scenario = fixture
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "log_in_reverse")
        .ok_or("no such scenario")?;
    let mut kevery = Kevery::new();
    let (inception, early) = scenario.steps.split_last().ok_or("no steps")?;
    for step in early {
        let message = Message::from_bytes(&decode_hex(&step.raw_hex)?)?;
        assert_eq!(kevery.process(&message, &now)?, Processed::Escrowed(Escrow::OutOfOrder));
    }
    let message = Message::from_bytes(&decode_hex(&inception.raw_hex)?)?;
    assert_eq!(kevery.process(&message, &now)?, Processed::Accepted);
    assert_eq!(kevery.process_escrows(&now)?, early.len());
    assert_eq!(kevery.escrowed_event_count()?, 0);
    Ok(())
}
