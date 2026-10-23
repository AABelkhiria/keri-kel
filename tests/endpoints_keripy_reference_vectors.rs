//! End role and location replies processed by the pinned keripy reference, replayed through the
//! port.
//!
//! Each scenario offers keripy events and `/end/role` and `/loc/scheme` replies in some order,
//! processing event and reply escrows after each, and records the outcome of every message and
//! everything keripy held afterwards, the end roles and locations it kept included. The port must
//! reach the same outcomes and hold the same. See `fixtures/endpoints-keripy/README.md`.

mod support;

use std::error::Error;

use keri_protocol::event::timestamp::Timestamp;
use serde::Deserialize;
use support::{REFERENCE_SHA, Scenario, replay};

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
        "/fixtures/endpoints-keripy/v1.json"
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
    assert_eq!(
        fixture.sources,
        ["src/keri/core/eventing.py", "src/keri/core/routing.py"]
    );
    Timestamp::parse(&fixture.now)?;
    Ok(())
}

#[test]
fn every_scenario_holds_what_keripy_holds() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    assert_eq!(fixture.scenarios.len(), 4);
    assert_eq!(replay(&fixture.scenarios, &now, |kevery| kevery)?, 17);
    Ok(())
}
