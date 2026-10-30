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
| `kevery` | Many identifiers' logs: routes messages, approves delegated events, and escrows what cannot be decided yet |
| `reply` | How a reply is verified and escrowed, for every route a `Kevery` keeps |
| `notice` | Key state notices: which `/ksn` replies a `Kevery` keeps, and whose it trusts |
| `endpoint` | End roles and locations: which `/end/role` and `/loc/scheme` replies a `Kevery` keeps |
| `observation` | Watcher registrations: which `/watcher` replies a `Kevery` keeps, and the OOBIs they queue |
| `query` | Answers to `logs`, `ksn` and `mbx` queries, and queries waiting for the log |
| `adjudication` | Whether watchers' reports agree with the local state |
| `codec` | Every record a store keeps, written as readable JSON bytes and read back |
| `store` | Where a `Kevery` keeps its state: traits, and an in-memory store |
| `error` | Why an event was refused, and whether waiting could help |

A `Kever` validates one identifier's log: inceptions, rotations and interactions, with numeric or
weighted thresholds, partial rotations, witnesses and recovery rotations. A `Kevery` holds many
identifiers' logs: it routes receipts, approves delegated events against their delegators' logs,
escrows what cannot be decided yet, keeps replies (key state notices, end roles, locations and
watcher registrations), answers queries and adjudicates watchers' reports. One keripy defect is not
followed: an older key state notice never replaces a newer one.

Nothing here reads a clock or a network: the first-seen time is an argument. A `Kevery` keeps its
state in a `MemoryStore` by default, or through `Kevery::with_store` in any type implementing the
`KelStore`, `EscrowStore`, `ReceiptStore` and `ReplyStore` traits.

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
