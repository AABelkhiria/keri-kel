#![no_main]
#![forbid(unsafe_code)]

use keri_kel::Kevery;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::stream::parse_stream;
use libfuzzer_sys::fuzz_target;

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
        let _ = kevery.process(message, &now);
        kevery.process_escrows(&now);
    }
    let escrowed = kevery.escrowed_events();
    let waiting = kevery.waiting_receipts();
    assert_eq!(
        kevery.process_escrows(&now),
        0,
        "a second escrow pass accepted something"
    );
    assert_eq!(kevery.escrowed_events(), escrowed);
    assert!(kevery.waiting_receipts() <= waiting);
    for message in &messages {
        if let Ok(event) = keri_kel::KeyEventFields::read(message.event()) {
            if let Some(kever) = kevery.kever(event.identifier()) {
                assert!(kever.state().is_ok(), "an accepted log could not write its state");
                if kever.delegator().is_some() {
                    let inception = kevery.logged(event.identifier(), 0);
                    assert!(
                        inception.is_some_and(|logged| logged.delegation().is_some()),
                        "a delegated inception was accepted without its delegating event"
                    );
                }
            }
        }
    }
});
