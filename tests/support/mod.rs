//! Replays keripy's log-processing scenarios through the port and compares what both hold.
//!
//! The fixtures under `fixtures/kevery-keripy`, `fixtures/delegation-keripy` and
//! `fixtures/out-of-order-keripy`, `fixtures/recovery-keripy` and
//! `fixtures/delegated-recovery-keripy`, `fixtures/validator-receipts-keripy` and
//! `fixtures/key-state-notices-keripy` and `fixtures/endpoints-keripy` share one shape:
//! each step is a message, the outcome the port must reach, and a snapshot of what keripy held
//! after processing it and its escrows.

use std::error::Error;

use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::sequence::SequenceNumber;
use keri_kel::{Escrow, KelError, Kevery, NoticeTrust, Processed};
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
    /// keripy's strict trust policy for key state notices, when the scenario applies it.
    #[serde(default)]
    pub(crate) trust: Option<Trust>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Trust {
    pub(crate) watchers: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct EndRoleSnapshot {
    pub(crate) controller: String,
    pub(crate) role: String,
    pub(crate) endpoint: String,
    pub(crate) allowed: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct LocationSnapshot {
    pub(crate) endpoint: String,
    pub(crate) scheme: String,
    pub(crate) url: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct NoticeSnapshot {
    pub(crate) identifier: String,
    pub(crate) source: String,
    pub(crate) state_json: String,
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
    #[serde(default)]
    pub(crate) key_state_notices: Vec<NoticeSnapshot>,
    #[serde(default)]
    pub(crate) escrowed_replies: usize,
    #[serde(default)]
    pub(crate) end_roles: Vec<EndRoleSnapshot>,
    #[serde(default)]
    pub(crate) locations: Vec<LocationSnapshot>,
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
    /// Validator receipts: validator, its event's sequence number and SAID, and signature, as qb64
    /// text, sorted.
    #[serde(default)]
    pub(crate) validator_receipts: Vec<String>,
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
        "Escrowed:UnverifiedTransferableReceipt" => {
            matches!(result, Ok(Processed::Escrowed(Escrow::UnverifiedTransferableReceipt)))
        }
        "ReceiptorEventMismatch" => matches!(result, Err(KelError::ReceiptorEventMismatch)),
        "ReceiptorEventHasNoKeys" => matches!(result, Err(KelError::ReceiptorEventHasNoKeys)),
        "ReceiptSignatureIndexOutOfRange" => matches!(result, Err(KelError::ReceiptSignatureIndexOutOfRange)),
        "Escrowed:UnverifiedReceipt" => matches!(result, Ok(Processed::Escrowed(Escrow::UnverifiedReceipt))),
        "StaleReceipt" => matches!(result, Err(KelError::StaleReceipt)),
        "PriorMismatch" => matches!(result, Err(KelError::PriorMismatch)),
        "SupersedingDelegationNotLater" => matches!(result, Err(KelError::SupersedingDelegationNotLater)),
        "KeyStateAccepted" => matches!(result, Ok(Processed::KeyStateAccepted)),
        "EndRoleAccepted" => matches!(result, Ok(Processed::EndRoleAccepted)),
        "LocationAccepted" => matches!(result, Ok(Processed::LocationAccepted)),
        "InvalidReply" => matches!(result, Err(KelError::Reply { .. })),
        "Escrowed:UnverifiedReply" => matches!(result, Ok(Processed::Escrowed(Escrow::UnverifiedReply))),
        "UnverifiedReply" => matches!(result, Err(KelError::UnverifiedReply)),
        "StaleKeyState" => matches!(result, Err(KelError::StaleKeyState)),
        "KeyStateMismatch" => matches!(result, Err(KelError::KeyStateMismatch)),
        "UntrustedKeyStateSource" => matches!(result, Err(KelError::UntrustedKeyStateSource)),
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
    let Some(kever) = kevery.kever(&prefix)? else {
        return Ok((None, Vec::new()));
    };
    let state = String::from_utf8(kever.state()?.to_sad()?.to_json_bytes()?)?;
    let mut events = Vec::new();
    for sequence_number in 0..=kever.sequence_number() {
        let Some(logged) = kevery.logged(&prefix, sequence_number)? else {
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
            validator_receipts: texts(logged.validator_receipts(), |receipt| {
                Ok(format!(
                    "{}{}{}{}",
                    receipt.validator().qb64()?,
                    SequenceNumber::new(receipt.sequence_number()).qb64()?,
                    receipt.said().qb64()?,
                    receipt.signature().qb64()?
                ))
            })?,
            delegation,
        });
    }
    Ok((Some(state), events))
}

pub(crate) fn compare(kevery: &Kevery, expected: &Snapshot, context: &str) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        kevery.escrowed_events()?,
        expected.escrowed_events,
        "{context}: escrowed events"
    );
    assert_eq!(
        kevery.waiting_receipts()?,
        expected.waiting_receipts,
        "{context}: waiting receipts"
    );
    assert_eq!(
        kevery.escrowed_replies()?,
        expected.escrowed_replies,
        "{context}: escrowed replies"
    );
    let mut notices = Vec::new();
    for identifier in &expected.states {
        let prefix = IdentifierPrefix::from_qb64(&identifier.identifier)?;
        for (source, notice) in kevery.key_state_notices(&prefix)? {
            notices.push(NoticeSnapshot {
                identifier: identifier.identifier.clone(),
                source,
                state_json: String::from_utf8(notice.state().to_sad()?.to_json_bytes()?)?,
            });
        }
    }
    notices.sort_by(|left, right| (&left.identifier, &left.source).cmp(&(&right.identifier, &right.source)));
    assert_eq!(notices, expected.key_state_notices, "{context}: key state notices");
    let mut end_roles = Vec::new();
    let mut locations = Vec::new();
    for identifier in &expected.states {
        let prefix = IdentifierPrefix::from_qb64(&identifier.identifier)?;
        for (role, endpoint, record) in kevery.end_roles(&prefix)? {
            end_roles.push(EndRoleSnapshot {
                controller: identifier.identifier.clone(),
                role: role.as_str().to_owned(),
                endpoint: endpoint.qb64()?,
                allowed: record.allowed(),
            });
        }
        for (scheme, record) in kevery.locations(&prefix)? {
            locations.push(LocationSnapshot {
                endpoint: identifier.identifier.clone(),
                scheme: scheme.as_str().to_owned(),
                url: record.url().to_owned(),
            });
        }
    }
    end_roles.sort_by(|left, right| {
        (&left.controller, &left.role, &left.endpoint).cmp(&(&right.controller, &right.role, &right.endpoint))
    });
    locations.sort_by(|left, right| (&left.endpoint, &left.scheme).cmp(&(&right.endpoint, &right.scheme)));
    assert_eq!(end_roles, expected.end_roles, "{context}: end roles");
    assert_eq!(locations, expected.locations, "{context}: locations");
    for identifier in &expected.states {
        let (state, events) = held(kevery, &identifier.identifier)?;
        assert_eq!(state, identifier.state_json, "{context}: key state");
        assert_eq!(events, identifier.events, "{context}: accepted events");
        let prefix = IdentifierPrefix::from_qb64(&identifier.identifier)?;
        let mut superseded: Vec<String> = kevery
            .superseded(&prefix)?
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
    kevery.process_escrows(now)?;
    Ok(result)
}

/// An empty set of logs, applying the scenario's trust policy.
pub(crate) fn kevery_for(scenario: &Scenario) -> Result<Kevery, Box<dyn Error>> {
    Ok(match &scenario.trust {
        None => Kevery::new(),
        Some(trust) => Kevery::new().trusting(NoticeTrust::Watchers(
            trust
                .watchers
                .iter()
                .map(|watcher| IdentifierPrefix::from_qb64(watcher))
                .collect::<Result<_, _>>()?,
        )),
    })
}

/// Replays every scenario from an empty set of logs, checking each step's outcome and what is
/// held after it, and returns how many steps were replayed. `between` runs after each step, before
/// the check: it may hand the logs on, or return them as they are.
pub(crate) fn replay(
    scenarios: &[Scenario],
    now: &Timestamp,
    between: impl Fn(Kevery) -> Kevery,
) -> Result<usize, Box<dyn Error>> {
    let mut steps = 0;
    for scenario in scenarios {
        assert_ne!(scenario.note, "");
        let mut kevery = kevery_for(scenario)?;
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
            kevery = between(kevery);
            compare(&kevery, &step.after, &context)?;
        }
    }
    Ok(steps)
}
