# KERI out-of-order and likely-duplicitous reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`Kevery.processEvent`, `escrowOOEvent`, `escrowLDEvent`,
  `processEscrows`, `processEscrowOutOfOrders` and `processEscrowDuplicitous`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. Stored signatures
  are qb64 text, sorted, as keripy's database returns them.

## Why keripy

keripy's `Kevery` decides what KERIA and keripy witnesses do with an event that arrives before
the events it follows, or that contradicts one already accepted. `src/kevery.rs` ports it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/out_of_order_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/out_of_order_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`: each scenario runs keripy's
`Kevery`, unmodified, over its own temporary keripy database, feeds it one message at a time the
way keripy's parser does, and runs `processEscrows` after each. keripy's clock is pinned.

Each step records the exact message bytes, the exception keripy raised if any, and a snapshot of
what keripy then held: each identifier's key state, the signatures stored for each accepted event,
the delegating event stored for each accepted delegated event, and how many events are escrowed,
the out-of-order and likely-duplicitous escrows included.

`rust_outcome` names what the port's `Kevery::process` must return. keripy signals an escrowed
event by raising, so `OutOfOrderError` and `LikelyDuplicitousError` correspond to the port's
out-of-order and likely-duplicitous outcomes.

## Contents

`scenarios` records six scenarios, 25 messages in all:

- `log_in_reverse`: a rotation and two interactions arrive before the inception they follow; once
  it is accepted, one escrow pass accepts them in sequence order.
- `gap_in_a_known_log`: the event after next waits until the next one is accepted.
- `out_of_order_and_partially_signed`: an early two-of-two interaction with one signature moves to
  the partially signed escrow once its predecessor is accepted, and its second signature completes
  it.
- `out_of_order_with_a_bad_signature`: an early event is kept without verification, since its key
  state is not known yet, and dropped once its predecessors are accepted and its signature fails.
- `out_of_order_delegated_rotation`: an early delegated rotation is retried without the seal
  source couple it arrived with, moves to the partially delegated escrow, and is approved by
  walking its delegator's log.
- `likely_duplicitous`: a second inception for a basic prefix, and a second interaction at an
  accepted number, are kept aside, once each however often they are offered, and never accepted.

Rust tests consume the checked-in fixture and require neither Python nor network access.
