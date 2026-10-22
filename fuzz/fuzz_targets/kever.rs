#![no_main]
#![forbid(unsafe_code)]

use keri_kel::Kever;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::stream::parse_stream;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Any stream: the first message may start a log and the rest may extend it. Nothing panics,
    // and a refused event leaves the state exactly as it was.
    let Ok(stamp) = Timestamp::parse("2021-01-01T00:00:00.000000+00:00") else {
        return;
    };
    let Ok(messages) = parse_stream(data) else {
        return;
    };
    let mut iter = messages.iter();
    let Some(first) = iter.next() else { return };
    let Ok(mut kever) = Kever::incept(first, stamp.clone()) else {
        return;
    };
    for message in iter {
        let before = kever.clone();
        if kever.update(message, stamp.clone()).is_err() {
            assert_eq!(kever, before, "a refused event changed the state");
        }
        assert!(kever.state().is_ok(), "an accepted log could not write its state");
    }
});
