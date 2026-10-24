# KERI query reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-24
- Sources: `src/keri/core/eventing.py` (`Kevery.processQuery`, `escrowQueryNotFoundEvent` and
  `processQueryNotFound`) and `src/keri/db/basing.py` (`clonePreIter`, `cloneEvtMsg`,
  `fullyWitnessed` and `fetchAllSealingEventByEventSeal`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. A replay's
  `messages_hex` are the messages keripy cued, each an event with its attachments in keripy's clone
  format.

## Why keripy

A query (`qry`) asks a witness or watcher for an identifier's log (`logs`), its key state (`ksn`) or
its mailbox (`mbx`). keripy's `Kevery` decides when it can answer and what with, and `src/query.rs`
ports it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/queries_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/queries_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`. Each scenario runs keripy's
`Kevery`, unmodified, over its own temporary keripy database, and feeds it events and queries one
at a time the way keripy's parser does. A query is signed as keripy's agents sign one: with a
transferable requester's latest establishment keys (`-H`), or, in one scenario, by a
non-transferable key alone. After each message `processEscrows` runs, which retries waiting
queries.

Each step records the exact message bytes, the exception keripy raised if any, the answers keripy
cued for the query (`keripy.answers`), the answers it cued for queries escrowed earlier
(`after.answered`), and a snapshot of what it then held, the waiting queries counted. An answer is
a replay (the messages keripy would send), a key state, or a mailbox opened.

`rust_outcome` names what the port's `Kevery::process` must return. keripy signals a waiting query
by raising `QueryNotFoundError`, which corresponds to the port's escrowed outcome.

## Contents

`scenarios` records five scenarios, 26 messages in all:

- `log_replays`: a log replayed whole, from its second first-seen event, and from an anchor one of
  its events holds; its key state and its mailbox; and a log query by an anchor no event holds,
  which waits.
- `queries_wait_for_the_log`: a key state query for an identifier not seen yet, and a log query
  for a sequence number the log has not reached, wait and are answered once the events arrive.
- `recovered_log`: after a recovery rotation, the log replays every event in the order first
  seen, the superseded ones included.
- `delegated_log`: a delegated identifier's log replays followed by its delegator's whole log.
- `non_transferable_requester`: a query signed by a non-transferable key is answered when the log
  holds what it asks for; when it does not, keripy raises `AttributeError` escrowing it, since it
  escrows queries under a transferable requester, and the port refuses it.

Rust tests compare each answer by the events replayed, their SAIDs and first-seen ordinals in
order, by the key state, or by the mailbox's identifier. They consume the checked-in fixture and
require neither Python nor network access.
