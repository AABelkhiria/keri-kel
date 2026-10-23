//! Key state adjudications decided by the pinned keripy reference, replayed through the port.
//!
//! Each case gives keripy's `Adjudicator` a local key state and what each watcher last reported,
//! and records the cue it emits: its kind, the watchers it names with their comparison, and for an
//! update the sequence number to catch up to. The port must decide the same. See
//! `fixtures/adjudication-keripy/README.md`.

use std::collections::BTreeMap;
use std::error::Error;

use keri_kel::{Adjudication, KelError, WatcherReport, adjudicate};
use keri_protocol::event::key_state::{KeyStateRecord, StateComparison};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::Sad;
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
    local: String,
    states: BTreeMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    note: String,
    threshold: Option<usize>,
    reports: Vec<Report>,
    keripy: Outcome,
}

#[derive(Debug, Deserialize)]
struct Report {
    watcher: String,
    state: Option<String>,
}

/// A watcher a cue names: the watcher, its comparison, and the reported sequence number and SAID.
type Named = (String, String, u128, String);

#[derive(Debug, Deserialize)]
struct Outcome {
    raised: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    named: Vec<Named>,
    #[serde(default)]
    sequence_number: Option<u128>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/adjudication-keripy/v1.json"
    )))?)
}

fn record(json: &str) -> Result<KeyStateRecord, Box<dyn Error>> {
    Ok(KeyStateRecord::from_sad(&Sad::from_json_bytes(json.as_bytes())?)?)
}

/// The watchers an adjudication names, in keripy's vocabulary, sorted.
fn named(reports: &[WatcherReport]) -> Result<Vec<Named>, Box<dyn Error>> {
    let mut named = reports
        .iter()
        .map(|report| -> Result<_, Box<dyn Error>> {
            let difference = report.difference();
            let comparison = match difference.comparison() {
                StateComparison::Even => "even",
                StateComparison::Ahead => "ahead",
                StateComparison::Behind => "behind",
                StateComparison::Duplicitous => "duplicitous",
            };
            Ok((
                report.watcher().qb64()?,
                comparison.to_owned(),
                difference.sequence_number(),
                difference.said().qb64()?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    named.sort();
    Ok(named)
}

#[test]
fn fixture_metadata_matches_the_pinned_keripy_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/keripy.git");
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.reference_version, "1.3.6");
    assert_ne!(fixture.generated_on, "");
    assert_eq!(fixture.sources, ["src/keri/app/watching.py"]);
    Ok(())
}

#[test]
fn every_case_decides_as_keripy_decides() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let local = record(fixture.states.get(&fixture.local).ok_or("no local state")?)?;
    assert_eq!(fixture.cases.len(), 13);
    for case in &fixture.cases {
        assert_ne!(case.note, "");
        let reports = case
            .reports
            .iter()
            .map(|report| -> Result<_, Box<dyn Error>> {
                let state = match &report.state {
                    Some(label) => Some(record(fixture.states.get(label).ok_or("no such state")?)?),
                    None => None,
                };
                Ok((IdentifierPrefix::from_qb64(&report.watcher)?, state))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = adjudicate(&local, &reports, case.threshold);
        let context = &case.name;
        if case.keripy.raised.is_some() {
            assert!(
                matches!(result, Err(KelError::ThresholdAboveWatchers { .. })),
                "{context}: got {result:?}"
            );
            continue;
        }
        let adjudication = result?;
        let (kind, reported, sequence_number) = match &adjudication {
            Adjudication::Consistent(reports) => (Some("keyStateConsistent"), named(reports)?, None),
            Adjudication::Lagging(reports) => (Some("keyStateLagging"), named(reports)?, None),
            Adjudication::Update { sequence_number, ahead } => {
                (Some("keyStateUpdate"), named(ahead)?, Some(*sequence_number))
            }
            Adjudication::Duplicitous(reports) => (Some("keyStateDuplicitous"), named(reports)?, None),
            Adjudication::Undecided => (None, Vec::new(), None),
        };
        assert_eq!(kind, case.keripy.kind.as_deref(), "{context}: kind");
        assert_eq!(reported, case.keripy.named, "{context}: named watchers");
        assert_eq!(
            sequence_number, case.keripy.sequence_number,
            "{context}: sequence number"
        );
    }
    Ok(())
}
