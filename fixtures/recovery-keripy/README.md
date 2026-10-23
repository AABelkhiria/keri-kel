# KERI recovery rotation reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`Kevery.processEvent`, `Kever.update`, `Kever.rotate` and
  `Kever.deriveBacks`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. Stored signatures
  are qb64 text, sorted, as keripy's database returns them.

## Why keripy

keripy's `Kever` decides when a rotation may supersede events already accepted, which is how a
controller recovers from compromised signing keys. `src/kever.rs` and `src/kevery.rs` port it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/recovery_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/recovery_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`: each scenario runs keripy's
`Kevery`, unmodified, over its own temporary keripy database, feeds it one message at a time the
way keripy's parser does, and runs `processEscrows` after each. keripy's clock is pinned.

Each step records the exact message bytes, the exception keripy raised if any, and a snapshot of
what keripy then held: each identifier's key state, the signatures stored for each accepted event,
the SAIDs of events a recovery superseded (`superseded`, from keripy's log of every event at each
sequence number, sorted), and how many events are escrowed.

`rust_outcome` names what the port's `Kevery::process` must return. keripy raises a plain
`ValidationError` for a refused recovery; `rust_outcome` names the port's error for it.

## Contents

`scenarios` records five scenarios, 21 messages in all:

- `recovery_supersedes_interactions`: a rotation at the second of three interactions' sequence
  number, following the first, supersedes the second and third; the log continues from it, and a
  superseded interaction offered again is likely duplicitous.
- `recovery_of_the_first_interaction`: a rotation following the inception supersedes the
  interaction after it.
- `recovery_with_the_wrong_prior`: a rotation naming the event it would supersede as its prior is
  refused.
- `recovery_gathers_signatures`: a two-of-two recovery rotation waits in the partially signed
  escrow until its second signature arrives.
- `recovery_keeps_the_witnesses`: keripy derives no witness changes for a rotation at or below the
  latest sequence number, so a recovery rotation's cuts and adds are ignored, the witnesses stay as
  they were, and its witness threshold is checked against them. The port does the same.

A delegated rotation superseding an accepted event follows separate superseding rules in keripy and
is not recorded here; the port refuses it until those rules are ported.

Rust tests consume the checked-in fixture and require neither Python nor network access.
