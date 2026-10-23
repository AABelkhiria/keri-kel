//! What a `Kevery` keeps lives in its store: a store handed to a new `Kevery` carries on where the
//! old one stopped, and a store that fails is reported as such, never taken for a refused event.

mod support;

use std::cell::Cell;
use std::error::Error;

use keri_kel::{
    EndRoleRecord, Escrow, EscrowStore, EscrowedEvent, EscrowedReply, KelError, KelStore, Kever, Kevery,
    KeyStateNotice, LocationRecord, LoggedEvent, MemoryStore, ReceiptStore, ReplyStore, StoreError, WaitingReceipt,
};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::stream::Message;
use serde::Deserialize;
use support::{REFERENCE_SHA, Scenario, decode_hex, replay};

#[derive(Debug, Deserialize)]
struct Fixture {
    reference_sha: String,
    now: String,
    scenarios: Vec<Scenario>,
}

fn fixture(json: &str) -> Result<Fixture, Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_str(json)?;
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    Ok(fixture)
}

/// Every fixture's scenarios, each replayed with its logs handed to a new `Kevery` after every
/// step, end where keripy ends.
#[test]
fn a_store_handed_on_carries_everything() -> Result<(), Box<dyn Error>> {
    let fixtures = [
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
    ];
    let mut steps = 0;
    for json in fixtures {
        let fixture = fixture(json)?;
        let now = Timestamp::parse(&fixture.now)?;
        steps += replay(&fixture.scenarios, &now, |kevery| {
            // The trust policy is configuration, carried over as an application would.
            let trust = kevery.trust().clone();
            Kevery::with_store(kevery.into_store()).trusting(trust)
        })?;
    }
    assert_eq!(steps, 193);
    Ok(())
}

/// A memory store that fails every write once told to.
#[derive(Default)]
struct Failing {
    inner: MemoryStore,
    failing: Cell<bool>,
}

impl Failing {
    fn write(&self) -> Result<(), StoreError> {
        if self.failing.get() {
            Err(StoreError::new("the disk is full"))
        } else {
            Ok(())
        }
    }
}

impl KelStore for Failing {
    fn kever(&self, identifier: &str) -> Result<Option<Kever>, StoreError> {
        self.inner.kever(identifier)
    }

    fn event(&self, identifier: &str, sequence_number: u128) -> Result<Option<LoggedEvent>, StoreError> {
        self.inner.event(identifier, sequence_number)
    }

    fn find_event(
        &self,
        identifier: &str,
        matches: &mut dyn FnMut(&LoggedEvent) -> bool,
    ) -> Result<Option<(u128, LoggedEvent)>, StoreError> {
        self.inner.find_event(identifier, matches)
    }

    fn superseded(&self, identifier: &str) -> Result<Vec<LoggedEvent>, StoreError> {
        self.inner.superseded(identifier)
    }

    fn accept(
        &mut self,
        identifier: &str,
        kever: Kever,
        sequence_number: u128,
        event: LoggedEvent,
    ) -> Result<(), StoreError> {
        self.write()?;
        self.inner.accept(identifier, kever, sequence_number, event)
    }

    fn update_event(&mut self, identifier: &str, sequence_number: u128, event: LoggedEvent) -> Result<(), StoreError> {
        self.write()?;
        self.inner.update_event(identifier, sequence_number, event)
    }
}

impl EscrowStore for Failing {
    fn escrowed(&self, identifier: &str, said: &str) -> Result<Option<EscrowedEvent>, StoreError> {
        self.inner.escrowed(identifier, said)
    }

    fn escrowed_for(&self, reason: Escrow) -> Result<Vec<(String, String, EscrowedEvent)>, StoreError> {
        self.inner.escrowed_for(reason)
    }

    fn put_escrowed(&mut self, identifier: &str, said: &str, event: EscrowedEvent) -> Result<(), StoreError> {
        self.write()?;
        self.inner.put_escrowed(identifier, said, event)
    }

    fn remove_escrowed(&mut self, identifier: &str, said: &str) -> Result<(), StoreError> {
        self.write()?;
        self.inner.remove_escrowed(identifier, said)
    }

    fn next_arrival(&mut self) -> Result<u64, StoreError> {
        self.write()?;
        self.inner.next_arrival()
    }

    fn escrowed_count(&self) -> Result<usize, StoreError> {
        self.inner.escrowed_count()
    }

    fn expire_escrowed(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        self.write()?;
        self.inner.expire_escrowed(cutoff)
    }
}

impl ReceiptStore for Failing {
    fn hold_receipt(&mut self, receipt: WaitingReceipt) -> Result<(), StoreError> {
        self.write()?;
        self.inner.hold_receipt(receipt)
    }

    fn take_receipts(&mut self) -> Result<Vec<WaitingReceipt>, StoreError> {
        self.write()?;
        self.inner.take_receipts()
    }

    fn receipt_count(&self) -> Result<usize, StoreError> {
        self.inner.receipt_count()
    }

    fn expire_receipts(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        self.write()?;
        self.inner.expire_receipts(cutoff)
    }
}

impl ReplyStore for Failing {
    fn end_role(&self, controller: &str, role: &str, endpoint: &str) -> Result<Option<EndRoleRecord>, StoreError> {
        self.inner.end_role(controller, role, endpoint)
    }

    fn end_roles(&self, controller: &str) -> Result<Vec<(String, String, EndRoleRecord)>, StoreError> {
        self.inner.end_roles(controller)
    }

    fn put_end_role(
        &mut self,
        controller: &str,
        role: &str,
        endpoint: &str,
        record: EndRoleRecord,
    ) -> Result<(), StoreError> {
        self.write()?;
        self.inner.put_end_role(controller, role, endpoint, record)
    }

    fn location(&self, endpoint: &str, scheme: &str) -> Result<Option<LocationRecord>, StoreError> {
        self.inner.location(endpoint, scheme)
    }

    fn locations(&self, endpoint: &str) -> Result<Vec<(String, LocationRecord)>, StoreError> {
        self.inner.locations(endpoint)
    }

    fn put_location(&mut self, endpoint: &str, scheme: &str, record: LocationRecord) -> Result<(), StoreError> {
        self.write()?;
        self.inner.put_location(endpoint, scheme, record)
    }

    fn key_state_notice(&self, identifier: &str, source: &str) -> Result<Option<KeyStateNotice>, StoreError> {
        self.inner.key_state_notice(identifier, source)
    }

    fn key_state_notices(&self, identifier: &str) -> Result<Vec<(String, KeyStateNotice)>, StoreError> {
        self.inner.key_state_notices(identifier)
    }

    fn put_key_state_notice(
        &mut self,
        identifier: &str,
        source: &str,
        notice: KeyStateNotice,
    ) -> Result<(), StoreError> {
        self.write()?;
        self.inner.put_key_state_notice(identifier, source, notice)
    }

    fn escrowed_reply(&self, said: &str) -> Result<Option<EscrowedReply>, StoreError> {
        self.inner.escrowed_reply(said)
    }

    fn escrowed_replies(&self) -> Result<Vec<(String, EscrowedReply)>, StoreError> {
        self.inner.escrowed_replies()
    }

    fn put_escrowed_reply(&mut self, said: &str, reply: EscrowedReply) -> Result<(), StoreError> {
        self.write()?;
        self.inner.put_escrowed_reply(said, reply)
    }

    fn remove_escrowed_reply(&mut self, said: &str) -> Result<(), StoreError> {
        self.write()?;
        self.inner.remove_escrowed_reply(said)
    }

    fn expire_escrowed_replies(&mut self, cutoff: &Timestamp) -> Result<usize, StoreError> {
        self.write()?;
        self.inner.expire_escrowed_replies(cutoff)
    }
}

/// A store that cannot write is reported with its own error, on offering an event and on
/// retrying escrows, and is never taken for a refused event that escrow processing would drop.
#[test]
fn a_failing_store_is_reported_not_taken_for_a_refusal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/out-of-order-keripy/v1.json"
    )))?;
    let now = Timestamp::parse(&fixture.now)?;
    let scenario = fixture
        .scenarios
        .iter()
        .find(|scenario| scenario.name == "gap_in_a_known_log")
        .ok_or("no such scenario")?;
    let message = |label: &str| -> Result<Message, Box<dyn Error>> {
        let step = scenario
            .steps
            .iter()
            .find(|step| step.label == label)
            .ok_or("no such step")?;
        Ok(Message::from_bytes(&decode_hex(&step.raw_hex)?)?)
    };

    let mut kevery = Kevery::with_store(Failing::default());
    kevery.process(&message("inception")?, &now)?;
    kevery.process(&message("second_interaction")?, &now)?;
    assert_eq!(kevery.escrowed_events()?, 1);

    kevery.store().failing.set(true);
    let error = kevery
        .process(&message("first_interaction")?, &now)
        .err()
        .ok_or("the event was accepted into a store that cannot write")?;
    assert!(matches!(error, KelError::Store { .. }), "got {error:?}");
    assert!(error.escrow().is_none());
    let source = error.source().ok_or("no source")?;
    assert_eq!(
        source.source().map(ToString::to_string).as_deref(),
        Some("the disk is full")
    );
    assert!(matches!(kevery.process_escrows(&now), Err(KelError::Store { .. })));

    kevery.store().failing.set(false);
    assert_eq!(kevery.escrowed_events()?, 1, "the waiting event was kept");
    kevery.process(&message("first_interaction")?, &now)?;
    assert_eq!(kevery.process_escrows(&now)?, 1);
    Ok(())
}
