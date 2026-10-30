#![no_main]
#![forbid(unsafe_code)]

use keri_kel::{KelError, Kevery};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::stream::parse_stream;
use libfuzzer_sys::fuzz_target;

/// The memory store never fails, so a store error is a bug.
fn held<T>(result: Result<T, KelError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("the memory store failed: {error}"),
    }
}

fuzz_target!(|data: &[u8]| {
    // Any stream of events and receipts, in any order: nothing panics, every accepted log can write
    // its state, every accepted delegated inception holds the delegating event that approved it,
    // and processing escrows twice in a row changes nothing the second time.
    let Ok(now) = Timestamp::parse("2021-01-01T00:00:00.000000+00:00") else {
        return;
    };
    let Ok(messages) = parse_stream(data) else {
        return;
    };
    let mut kevery = Kevery::new();
    for message in &messages {
        if let Err(KelError::Store { .. }) = kevery.process(message, &now) {
            panic!("the memory store failed");
        }
        held(kevery.process_escrows(&now));
    }
    let escrowed = held(kevery.escrowed_event_count());
    let waiting = held(kevery.waiting_receipt_count());
    assert_eq!(
        held(kevery.process_escrows(&now)),
        0,
        "a second escrow pass accepted something"
    );
    assert_eq!(held(kevery.escrowed_event_count()), escrowed);
    assert!(held(kevery.waiting_receipt_count()) <= waiting);
    for message in &messages {
        if let Ok(event) = keri_kel::KeyEventFields::read(message.event()) {
            if let Some(kever) = held(kevery.kever(event.identifier())) {
                assert!(kever.state().is_ok(), "an accepted log could not write its state");
                if kever.delegator().is_some() {
                    let inception = held(kevery.logged(event.identifier(), 0));
                    assert!(
                        inception.is_some_and(|logged| logged.delegation().is_some()),
                        "a delegated inception was accepted without its delegating event"
                    );
                }
            }
        }
    }
});
