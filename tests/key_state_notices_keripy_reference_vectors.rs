//! Key state notices processed by the pinned keripy reference, replayed through the port.
//!
//! Each scenario offers keripy events and `/ksn` replies in some order, processing event and reply
//! escrows after each, and records the outcome of every message and everything keripy held
//! afterwards, the notices it kept included. The port must reach the same outcomes and hold the
//! same. See `fixtures/key-state-notices-keripy/README.md`.

mod support;

use std::error::Error;

use keri_kel::{Adjudication, KelError, Kevery};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use serde::Deserialize;
use support::{REFERENCE_SHA, Scenario, kevery_for, offer, replay};

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
    divergence_older_notice: Scenario,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/key-state-notices-keripy/v1.json"
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
    assert_eq!(fixture.scenarios.len(), 5);
    assert_eq!(replay(&fixture.scenarios, &now, |kevery| kevery)?, 19);
    Ok(())
}

/// keripy keeps a notice made earlier than the one it replaces; the port refuses it and keeps
/// the newer one.
#[test]
fn an_older_notice_does_not_replace_a_newer_one() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let divergence = &fixture.divergence_older_notice;
    assert_eq!(divergence.name, "older_notice_after_a_newer_one");
    assert_ne!(divergence.note, "");
    let (older, earlier) = divergence.steps.split_last().ok_or("no steps")?;
    let mut kevery = kevery_for(divergence)?;
    for step in earlier {
        offer(&mut kevery, step, &now)??;
    }
    let reported = |snapshot: &support::Snapshot| -> Result<String, Box<dyn Error>> {
        let notice = snapshot.key_state_notices.first().ok_or("no notice kept")?;
        let state: serde_json::Value = serde_json::from_str(&notice.state_json)?;
        Ok(state
            .get("s")
            .and_then(serde_json::Value::as_str)
            .ok_or("no sequence number")?
            .to_owned())
    };
    assert_eq!(reported(&older.after)?, "0", "keripy keeps the older report");

    let result = offer(&mut kevery, older, &now)?;
    assert!(matches!(result, Err(KelError::UnverifiedReply)), "got {result:?}");
    let notice = earlier.last().ok_or("no newer notice")?;
    let identifier =
        IdentifierPrefix::from_qb64(&notice.after.key_state_notices.first().ok_or("no notice")?.identifier)?;
    let kept = kevery.key_state_notices(&identifier)?;
    let (_, kept) = kept.first().ok_or("the port kept no notice")?;
    assert_eq!(kept.state().sequence_number(), 1, "the port keeps the newer report");
    assert_eq!(reported(&notice.after)?, "1");
    Ok(())
}

/// A `Kevery` adjudicates from the notices it kept: the witness's and the controller's report of
/// the state at the inception agree with the local log.
#[test]
fn a_kevery_adjudicates_from_the_notices_it_kept() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let now = Timestamp::parse(&fixture.now)?;
    let scenario = fixture
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "witness_and_controller_report")
        .ok_or("no such scenario")?;
    let mut kevery = Kevery::new();
    for step in &scenario.steps {
        offer(&mut kevery, step, &now)??;
    }
    let kept = &scenario.steps.last().ok_or("no steps")?.after.key_state_notices;
    let identifier = IdentifierPrefix::from_qb64(&kept.first().ok_or("no notice")?.identifier)?;
    let watchers = kept
        .iter()
        .map(|notice| IdentifierPrefix::from_qb64(&notice.source))
        .collect::<Result<Vec<_>, _>>()?;
    let Adjudication::Consistent(reports) = kevery.adjudicate(&identifier, &watchers, None)? else {
        return Err("the reports were not consistent".into());
    };
    assert_eq!(reports.len(), 2);
    assert!(matches!(
        kevery.adjudicate(&identifier, &watchers, Some(3)),
        Err(KelError::ThresholdAboveWatchers {
            threshold: 3,
            watchers: 2
        })
    ));
    Ok(())
}
