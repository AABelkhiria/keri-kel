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
| `reply` | How a reply is verified and escrowed, for every route a `Kevery` keeps |
| `notice` | Key state notices: which `/ksn` replies a `Kevery` keeps, and whose it trusts |
| `endpoint` | End roles and locations: which `/end/role` and `/loc/scheme` replies a `Kevery` keeps |
| `observation` | Watcher registrations: which `/watcher` replies a `Kevery` keeps, and the OOBIs they queue |
| `query` | Answers to `logs`, `ksn` and `mbx` queries, and queries waiting for the log |
| `adjudication` | Whether watchers' reports of an identifier agree with the local state, lag, call for an update, or show duplicity |
| `store` | Where a `Kevery` keeps its logs, escrows, waiting receipts and notices: traits, and an in-memory store |
| `error` | Why an event was refused, and whether waiting could help |

A `Kever` accepts:

- inceptions, rotations and interactions;
- signing thresholds, numeric or weighted, against the keys in force;
- rotations that reveal enough of the keys the prior establishment event committed to, including
  partial rotations;
- witnessed events whose witness signatures are attached, against the witness threshold;
- witness lists changed by rotation, and the `EO` and `DND` configuration traits;
- recovery rotations, which supersede interactions accepted since the latest establishment event.

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

A recovery rotation leaves the events it superseded in the `Kevery`, apart from the log. A
delegated rotation may supersede the latest delegated rotation when its delegating event is later
in the delegator's log, or the latest event when that is an interaction at its number. keripy
documents further cases that its code refuses; the port refuses them too, so that both hold the
same events (see `fixtures/delegated-recovery-keripy/README.md`).

Receipts from validators, transferable identifiers such as watchers, are verified against the keys
of the validator's establishment event they name and stored with the event, whether they arrive in
a receipt or attached to the event. A receipt waits while the validator's event is not accepted.

A `Kevery` also keeps key state notices, `/ksn` replies in which a witness, a watcher or the
controller reports an identifier's state: the latest from each source, once it is signed by that
source, newer than the last one kept from it, and consistent with the local log. By default it
trusts any source, as keripy's witnesses do; `NoticeTrust::Watchers` keeps only the identifier's,
its witnesses' and the configured watchers', as keripy's controllers do. One keripy defect is not
followed: keripy never compares a notice's date with the one it replaces, and keeps older ones.

A `Kevery` also keeps where identifiers are served: end role grants and withdrawals, signed by
the controller, per controller, role and endpoint, and locations, signed by the endpoint, per
endpoint and scheme, the latest of each, as keripy does. It keeps watcher registrations too, a
controller asking a watcher to start or stop observing an identifier, and queues the OOBIs they
give.

A `Kevery` answers queries as keripy does: `logs` with the events to replay, in the order first
seen and superseded ones included, followed by the delegator's log; `ksn` with the key state; and
`mbx` by opening the mailbox. A query the log cannot answer yet waits and is answered by
`process_escrows` once it can; answers are taken with `take_answers`, and `LoggedEvent::replay`
writes each replayed event exactly as keripy's replay does. Deciding who may ask is the caller's.

`adjudicate` compares what an identifier's watchers last reported with the local state, as keripy's
`Adjudicator` does: duplicity first, then watchers ahead, which call for an update when enough of
them agree, then watchers behind. `Kevery::adjudicate` does so from the notices it kept.

Every message kind a key event log needs is processed: inceptions, rotations and interactions,
delegated or not, receipts from witnesses, non-transferable identifiers and validators, key state
notices, end roles, locations, watcher registrations, and queries.

Nothing here reads a clock or a network. The first-seen time is an argument. A `Kever` holds its
state in the value. A `Kevery` keeps everything in a store: `Kevery::new()` keeps it in memory, and
`Kevery::with_store` takes any type implementing the `KelStore`, `EscrowStore` and `ReceiptStore`
traits, such as one backed by a database. The validation rules stay in `Kevery`; a store only keeps
what it is given.

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
