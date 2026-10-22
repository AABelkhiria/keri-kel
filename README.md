# keri-kel

KERI key event log validation in Rust: accepting signed events into an identifier's log and
deriving its key state. The rules and their order match
[keripy](https://github.com/WebOfTrust/keripy)'s `Kever`, checked against fixtures it generates by
validating the same logs.

Built on [keri-cesr](https://crates.io/crates/keri-cesr) and
[keri-protocol](https://crates.io/crates/keri-protocol), which build, parse and sign the events
this crate validates.

## Modules

| Module | Purpose |
|---|---|
| `event` | Reads a key event off the wire, verifying its SAID and, for an inception, its prefix |
| `kever` | One identifier's key state, extended event by event under keripy's rules |
| `kevery` | Many identifiers' logs: routes events and receipts, approves delegated events against their delegators' logs, and escrows what cannot be decided yet |
| `error` | Why an event was refused, and whether waiting could help |

A `Kever` accepts:

- inceptions, rotations and interactions;
- signing thresholds, numeric or weighted, against the keys in force;
- rotations that reveal enough of the keys the prior establishment event committed to, including
  partial rotations;
- witnessed events whose witness signatures are attached, against the witness threshold;
- witness lists changed by rotation, and the `EO` and `DND` configuration traits.

A `Kevery` holds many identifiers' logs. It accepts each identifier's events in turn, adds the
signatures a duplicate or a receipt brings to the stored event, and keeps an event that is short of
controller or witness signatures, with everything offered for it, until later offers and receipts
complete it. It accepts a delegated inception, or a rotation of a delegated identifier, once the
delegator's log holds an event anchoring a seal of it, and stores that delegating event with it;
until then the event waits too. A `Kever` on its own cannot see a delegator's log, so it refuses
delegated events as waiting for their delegator.

An event that arrives before the events it follows waits for them, unverified, and is retried in
sequence order once they are accepted. An event contradicting one already accepted is kept aside as
likely duplicitous and never accepted.

Not covered yet: recovery rotations, and receipts from transferable identifiers.

Nothing here reads a clock, a database or a network. The first-seen time is an argument and the
state lives in the value.

## Use

```rust
use keri_kel::Kever;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::stream::parse_stream;

fn validate(stream: &[u8], now: Timestamp) -> Result<Kever, Box<dyn std::error::Error>> {
    let messages = parse_stream(stream)?;
    let (inception, rest) = messages.split_first().ok_or("empty stream")?;
    let mut kever = Kever::incept(inception, now.clone())?;
    for message in rest {
        kever.update(message, now.clone())?;
    }
    Ok(kever)
}
```

## Prerequisites

- Rust 1.97 or newer (`rustup` installs the toolchain pinned in `rust-toolchain.toml`).
- Nightly Rust and `cargo-fuzz`, only for fuzzing.
- `uv` and libsodium, only to regenerate the fixtures.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test
cargo deny check
```

## Reference fixtures

`fixtures/` holds keripy's decisions over the same logs, generated at the commit pinned in
`tools/reference-vectors/pyproject.toml` and locked in `uv.lock`. Tests read the fixtures and never
need Python or the network. Each fixture directory has a README with its provenance.

```bash
uv sync --locked --project tools/reference-vectors
uv run --locked --project tools/reference-vectors python tools/reference-vectors/regenerate.py --check
```

## Fuzzing

```bash
cargo +nightly fuzz run kever
cargo +nightly fuzz run kevery
```

## License

Either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are dual licensed the same way unless you say otherwise.
