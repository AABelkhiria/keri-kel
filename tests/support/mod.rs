//! Replays keripy's log-processing scenarios through the port and compares what both hold.
//!
//! The fixtures under `fixtures/kevery-keripy`, `fixtures/delegation-keripy` and
//! `fixtures/out-of-order-keripy`, `fixtures/recovery-keripy` and
//! `fixtures/delegated-recovery-keripy` share one shape:
//! each step is a message, the outcome the port must reach, and a snapshot of what keripy held
//! after processing it and its escrows.

use std::error::Error;

use keri_cesr::crypto::signature::IndexedSignature;
use keri_kel::{Escrow, KelError, Kevery, Processed};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::stream::Message;
use serde::Deserialize;

pub(crate) const REFERENCE_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";

#[derive(Debug, Deserialize)]
pub(crate) struct Scenario {
    pub(crate) name: String,
    pub(crate) note: String,
    pub(crate) steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Step {
    pub(crate) label: String,
    pub(crate) raw: String,
    pub(crate) raw_hex: String,
    pub(crate) rust_outcome: String,
    pub(crate) keripy: Raised,
    pub(crate) after: Snapshot,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Raised {
    pub(crate) raised: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Snapshot {
    pub(crate) states: Vec<IdentifierSnapshot>,
    pub(crate) escrowed_events: usize,
    pub(crate) waiting_receipts: usize,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IdentifierSnapshot {
    pub(crate) identifier: String,
    pub(crate) state_json: Option<String>,
    pub(crate) events: Vec<EventSnapshot>,
    /// The SAIDs of events recovery rotations superseded, sorted.
    #[serde(default)]
    pub(crate) superseded: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct EventSnapshot {
    pub(crate) sequence_number: u128,
    pub(crate) said: String,
    pub(crate) signatures: Vec<String>,
    pub(crate) witness_signatures: Vec<String>,
    pub(crate) receipts: Vec<String>,
    /// The delegating event stored with a delegated event.
    #[serde(default)]
    pub(crate) delegation: Option<Delegation>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct Delegation {
    pub(crate) sequence_number: u128,
    pub(crate) said: String,
}

pub(crate) fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
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

pub(crate) fn outcome_matches(result: &Result<Processed, KelError>, expected: &str) -> bool {
    match expected {
        "Accepted" => matches!(result, Ok(Processed::Accepted)),
        "Duplicate" => matches!(result, Ok(Processed::Duplicate)),
        "Receipted" => matches!(result, Ok(Processed::Receipted)),
        "Escrowed:PartiallySigned" => matches!(result, Ok(Processed::Escrowed(Escrow::PartiallySigned))),
        "Escrowed:PartiallyWitnessed" => matches!(result, Ok(Processed::Escrowed(Escrow::PartiallyWitnessed))),
        "Escrowed:PartiallyDelegated" => matches!(result, Ok(Processed::Escrowed(Escrow::PartiallyDelegated))),
        "Escrowed:OutOfOrder" => matches!(result, Ok(Processed::Escrowed(Escrow::OutOfOrder))),
        "Escrowed:LikelyDuplicitous" => matches!(result, Ok(Processed::Escrowed(Escrow::LikelyDuplicitous))),
        "Escrowed:UnverifiedReceipt" => matches!(result, Ok(Processed::Escrowed(Escrow::UnverifiedReceipt))),
        "StaleReceipt" => matches!(result, Err(KelError::StaleReceipt)),
        "PriorMismatch" => matches!(result, Err(KelError::PriorMismatch)),
        "SupersedingDelegationNotLater" => matches!(result, Err(KelError::SupersedingDelegationNotLater)),
        "UndelegatedRotation" => matches!(result, Err(KelError::UndelegatedRotation)),
        "DelegationForbidden" => matches!(result, Err(KelError::DelegationForbidden)),
        "DelegationSourceAtInception" => matches!(result, Err(KelError::DelegationSourceAtInception)),
        _ => false,
    }
}

fn texts<T>(items: &[T], text: impl Fn(&T) -> Result<String, Box<dyn Error>>) -> Result<Vec<String>, Box<dyn Error>> {
    let mut texts = items.iter().map(text).collect::<Result<Vec<_>, _>>()?;
    texts.sort();
    Ok(texts)
}

/// What the port holds for one identifier, in the fixtures' vocabulary.
pub(crate) fn held(kevery: &Kevery, identifier: &str) -> Result<(Option<String>, Vec<EventSnapshot>), Box<dyn Error>> {
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
        let indexed = |signature: &IndexedSignature| -> Result<String, Box<dyn Error>> { Ok(signature.qb64()?) };
        let delegation = match logged.delegation() {
            Some(couple) => Some(Delegation {
                sequence_number: couple.sequence_number().value(),
                said: couple.said().qb64()?,
            }),
            None => None,
        };
        events.push(EventSnapshot {
            sequence_number,
            said: logged.event().said().unwrap_or_default().to_owned(),
            signatures: texts(logged.signatures(), indexed)?,
            witness_signatures: texts(logged.witness_signatures(), indexed)?,
            receipts: texts(logged.receipts(), |couple| {
                Ok(format!("{}{}", couple.verifier().qb64()?, couple.signature().qb64()?))
            })?,
            delegation,
        });
    }
    Ok((Some(state), events))
}

pub(crate) fn compare(kevery: &Kevery, expected: &Snapshot, context: &str) -> Result<(), Box<dyn Error>> {
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
        assert_eq!(events, identifier.events, "{context}: accepted events");
        let prefix = IdentifierPrefix::from_qb64(&identifier.identifier)?;
        let mut superseded: Vec<String> = kevery
            .superseded(&prefix)
            .iter()
            .map(|logged| logged.event().said().unwrap_or_default().to_owned())
            .collect();
        superseded.sort();
        assert_eq!(superseded, identifier.superseded, "{context}: superseded events");
    }
    Ok(())
}

/// Offers one step's message, then processes escrows, as the generator did.
pub(crate) fn offer(
    kevery: &mut Kevery,
    step: &Step,
    now: &Timestamp,
) -> Result<Result<Processed, KelError>, Box<dyn Error>> {
    let raw = decode_hex(&step.raw_hex)?;
    assert_eq!(raw, step.raw.as_bytes(), "step {} raw and raw_hex disagree", step.label);
    let message = Message::from_bytes(&raw)?;
    let result = kevery.process(&message, now);
    kevery.process_escrows(now);
    Ok(result)
}

/// Replays every scenario from an empty set of logs, checking each step's outcome and what is
/// held after it, and returns how many steps were replayed.
pub(crate) fn replay(scenarios: &[Scenario], now: &Timestamp) -> Result<usize, Box<dyn Error>> {
    let mut steps = 0;
    for scenario in scenarios {
        assert_ne!(scenario.note, "");
        let mut kevery = Kevery::new();
        for step in &scenario.steps {
            steps += 1;
            let context = format!("{}/{}", scenario.name, step.label);
            let result = offer(&mut kevery, step, now)?;
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
    Ok(steps)
}
