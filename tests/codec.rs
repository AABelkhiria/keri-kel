//! Every record a store keeps survives being written as bytes and read back: replaying every
//! keripy fixture, each record the store holds after each step comes back equal.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Debug;

use keri_kel::{
    Escrow, EscrowStore, KelError, KelStore, Kevery, MemoryStore, NoticeTrust, ReceiptStore, Record, ReplyStore,
};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::stream::Message;
use serde_json::Value;

const FIXTURES: [&str; 10] = [
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/kevery-keripy/v1.json")),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/delegation-keripy/v1.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/out-of-order-keripy/v1.json"
    )),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/recovery-keripy/v1.json")),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/delegated-recovery-keripy/v1.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/validator-receipts-keripy/v1.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/key-state-notices-keripy/v1.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/endpoints-keripy/v1.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/observations-keripy/v1.json"
    )),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/queries-keripy/v1.json")),
];

const ESCROWS: [Escrow; 5] = [
    Escrow::OutOfOrder,
    Escrow::PartiallySigned,
    Escrow::PartiallyWitnessed,
    Escrow::PartiallyDelegated,
    Escrow::LikelyDuplicitous,
];

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    (0..input.len())
        .step_by(2)
        .map(|index| {
            let pair = input.get(index..index + 2).ok_or("odd hexadecimal")?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

/// How many records of each type were round-tripped.
type Checked = BTreeMap<&'static str, usize>;

/// Writes `record` as bytes, reads it back, and counts it by type.
fn round_trip<T: Record + PartialEq + Debug>(record: &T, checked: &mut Checked) -> Result<(), Box<dyn Error>> {
    let read = T::from_bytes(&record.to_bytes()?)?;
    assert_eq!(&read, record);
    *checked.entry(std::any::type_name::<T>()).or_default() += 1;
    Ok(())
}

/// Round-trips every record the store holds for `identifiers`, and every escrowed one.
fn check(store: &mut MemoryStore, identifiers: &BTreeSet<String>, checked: &mut Checked) -> Result<(), Box<dyn Error>> {
    for identifier in identifiers {
        if let Some(kever) = store.kever(identifier)? {
            round_trip(&kever, checked)?;
        }
        for (_, logged) in store.events(identifier)? {
            round_trip(&logged, checked)?;
        }
        for logged in store.superseded(identifier)? {
            round_trip(&logged, checked)?;
        }
        for (_, notice) in store.key_state_notices(identifier)? {
            round_trip(&notice, checked)?;
        }
        for (_, _, record) in store.end_roles(identifier)? {
            round_trip(&record, checked)?;
        }
        for (_, record) in store.locations(identifier)? {
            round_trip(&record, checked)?;
        }
        for (_, _, record) in store.observations(identifier)? {
            round_trip(&record, checked)?;
        }
    }
    for reason in ESCROWS {
        for (_, _, escrowed) in store.escrowed_for(reason)? {
            round_trip(&escrowed, checked)?;
        }
    }
    for (_, escrowed) in store.escrowed_replies()? {
        round_trip(&escrowed, checked)?;
    }
    for (_, _, escrowed) in store.escrowed_queries()? {
        round_trip(&escrowed, checked)?;
    }
    let receipts = store.take_receipts()?;
    for receipt in &receipts {
        round_trip(receipt, checked)?;
    }
    for receipt in receipts {
        store.hold_receipt(receipt)?;
    }
    Ok(())
}

fn trust(scenario: &Value) -> Result<NoticeTrust, Box<dyn Error>> {
    let Some(watchers) = scenario.pointer("/trust/watchers").and_then(Value::as_array) else {
        return Ok(NoticeTrust::AnySource);
    };
    Ok(NoticeTrust::Watchers(
        watchers
            .iter()
            .map(|watcher| {
                Ok(IdentifierPrefix::from_qb64(
                    watcher.as_str().ok_or("watcher not text")?,
                )?)
            })
            .collect::<Result<_, Box<dyn Error>>>()?,
    ))
}

#[test]
fn every_stored_record_survives_bytes() -> Result<(), Box<dyn Error>> {
    let mut checked = Checked::new();
    for fixture in FIXTURES {
        let fixture: Value = serde_json::from_str(fixture)?;
        let now = Timestamp::parse(fixture.get("now").and_then(Value::as_str).ok_or("no time")?)?;
        for scenario in fixture
            .get("scenarios")
            .and_then(Value::as_array)
            .ok_or("no scenarios")?
        {
            let trust = trust(scenario)?;
            let mut kevery = Kevery::new().trusting(trust.clone());
            let steps = scenario.get("steps").and_then(Value::as_array).ok_or("no steps")?;
            for step in steps {
                let raw = decode_hex(step.get("raw_hex").and_then(Value::as_str).ok_or("no bytes")?)?;
                let result = kevery.process(&Message::from_bytes(&raw)?, &now);
                assert!(!matches!(result, Err(KelError::Store { .. })), "{result:?}");
                kevery.process_escrows(&now)?;
                let identifiers: BTreeSet<String> = step
                    .pointer("/after/states")
                    .and_then(Value::as_array)
                    .ok_or("no states")?
                    .iter()
                    .filter_map(|state| state.get("identifier").and_then(Value::as_str).map(str::to_owned))
                    .collect();
                let mut store = kevery.into_store();
                check(&mut store, &identifiers, &mut checked)?;
                kevery = Kevery::with_store(store).trusting(trust.clone());
            }
        }
    }
    // Every kind of record a store keeps came up, with the type's name as `type_name` writes it.
    assert_eq!(checked.len(), 10, "record types checked: {checked:?}");
    Ok(())
}

#[test]
fn a_damaged_record_is_refused() {
    assert!(matches!(
        keri_kel::Kever::from_bytes(b"{\"identifier\":\"not a prefix\"}"),
        Err(KelError::Record { .. })
    ));
    assert!(matches!(
        keri_kel::LoggedEvent::from_bytes(b"not json"),
        Err(KelError::Record { .. })
    ));
}
