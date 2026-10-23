//! Message sequences processed by the pinned keripy reference, replayed through the port.
//!
//! Each scenario offers keripy's `Kevery` a sequence of events and receipts, processing escrows
//! after each, and records the outcome of every message and everything keripy held afterwards. The
//! port must reach the same outcomes and hold the same key states, the same stored signatures for
//! every accepted event, and the same number of events and receipts waiting. See
//! `fixtures/kevery-keripy/README.md`.

mod support;

use std::error::Error;

use keri_kel::Kevery;
use keri_protocol::event::timestamp::Timestamp;
use serde::Deserialize;
use support::{REFERENCE_SHA, Scenario, Step, held, offer, outcome_matches, replay};

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
struct Divergence {
    name: String,
    note: String,
    steps: Vec<Step>,
    promoted_witness: String,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/kevery-keripy/v1.json"
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
    assert_eq!(fixture.scenarios.len(), 4);
    assert_eq!(replay(&fixture.scenarios, &now, |kevery| kevery)?, 15);
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
    assert_eq!(kevery.escrowed_events()?, 1);
    assert_eq!(
        kevery.expire_escrows(&now)?,
        0,
        "nothing escrowed at the cutoff expires"
    );
    assert_eq!(
        kevery.expire_escrows(&Timestamp::parse("2021-01-01T00:00:00.000001+00:00")?)?,
        1
    );
    assert_eq!(kevery.escrowed_events()?, 0);
    Ok(())
}
