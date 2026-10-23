# KERI key state notice reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-23
- Sources: `src/keri/core/eventing.py` (`Kevery.processReplyKeyStateNotice` and `updateKeyState`)
  and `src/keri/core/routing.py` (`Revery.processReply`, `acceptReply`, `escrowReply` and
  `processEscrowReply`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. A kept notice's
  state is the key state record as keripy's `asdict` writes it.

## Why keripy

A key state notice is a reply on route `/ksn/{source}` in which a witness, a watcher or the
controller reports an identifier's key state. keripy's `Kevery` decides which notices to keep, and
a watcher compares them to find identifiers that are lagging or duplicitous. `src/notice.rs` ports
it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/key_state_notices_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/key_state_notices_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`, which wires a keripy `Revery` to
its `Kevery` and registers the `Kevery`'s reply routes, as keripy's agents do. Each scenario runs
them, unmodified, over its own temporary keripy database, feeds them one message at a time the way
keripy's parser does, and runs both `Kevery.processEscrows` and `Revery.processEscrowReply` after
each. keripy's clock is pinned; each notice's state is the one keripy itself derives for the
reported events.

Each step records the exact message bytes, the exception keripy raised if any, and a snapshot of
what keripy then held: each identifier's key state and events, the notices kept (from keripy's
`knas` and `ksns` tables), and how many replies wait in its reply escrow. A scenario that applies
keripy's strict trust policy (`lax=False`) records it under `trust`, with the watchers a local
identifier configures.

`rust_outcome` names what the port's `Kevery::process` must return. keripy raises
`UnverifiedReplyError` both when a reply waits and when no signature establishes it, so
`rust_outcome` says which.

## Contents

`scenarios` records five scenarios, 19 messages in all:

- `witness_and_controller_report`: a witness, signing as its key, and the controller, signing with
  its inception's keys, each report the state; both notices are kept, one per source.
- `notices_against_the_local_log`: a notice ahead of the local log is kept; once the log has caught
  up, a notice of an earlier state is stale, and one reporting another event at a number the log
  holds is refused.
- `notice_from_an_unknown_signer`: a transferable source's notice waits in the reply escrow until
  the source's inception is accepted.
- `notices_not_signed_by_their_source`: a notice whose signature fails, and one signed by someone
  other than the source its route names, are not kept.
- `trusted_sources_only`: with the strict trust policy, a stranger's notice is refused, and the
  identifier's, a witness's and a configured watcher's are kept.

`divergence_older_notice` records the one behaviour the port does not follow. keripy looks up the
notice it kept before from a source by the reported event's SAID, while it stores replies under
their own SAIDs, so it finds none, compares no dates, and keeps a notice made earlier than the one
it replaces. The port compares reply dates, as keripy's best-available-data rule intends, and
refuses the older notice.

Rust tests consume the checked-in fixture and require neither Python nor network access.
