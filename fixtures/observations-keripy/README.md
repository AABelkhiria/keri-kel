# KERI watcher registration reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-23
- Sources: `src/keri/core/eventing.py` (`Kevery.processReplyAddWatched` and `updateWatched`) and
  `src/keri/core/routing.py` (`Revery.processReply`, `acceptReply`, `escrowReply` and
  `processEscrowReply`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load.

## Why keripy

A `/watcher/{watcher}/add` reply is a controller asking a watcher to observe an identifier, and
`/watcher/{watcher}/cut` asks it to stop; keripy's `kli watcher add` sends them. keripy's `Kevery`
decides which to keep, and `src/observation.rs` ports it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/observations_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/observations_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`, which wires a keripy `Revery` to
its `Kevery` and registers the `Kevery`'s reply routes, as keripy's agents do. Each scenario runs
them, unmodified, over its own temporary keripy database, feeds them one message at a time the way
keripy's parser does, and runs both `Kevery.processEscrows` and `Revery.processEscrowReply` after
each. keripy's clock is pinned.

Each step records the exact message bytes, the exception keripy raised if any, and a snapshot of
what keripy then held: identifiers' key states and events, the observations kept (from keripy's
`obvs` table, whether each is enabled), the OOBIs queued for resolution (from its `oobis` table),
and how many replies wait in its reply escrow.

`rust_outcome` names what the port's `Kevery::process` must return. keripy raises
`UnverifiedReplyError` both when a reply waits and when no signature establishes it, so
`rust_outcome` says which.

## Contents

`scenarios` records four scenarios, 13 messages in all:

- `observation_started_and_stopped`: a controller asks a watcher to observe an identifier, giving
  an OOBI for it, which is queued, then stops the observation in a later reply; offered again, the
  stop is not newer than itself and the start is older, so neither is kept again.
- `registration_signed_by_the_watcher`: a registration signed by the watcher rather than the
  controller is not kept.
- `registration_before_the_controller`: a registration waits in the reply escrow until the
  controller's inception is accepted.
- `observations_kept_apart`: observations of two identifiers by one watcher, and of one identifier
  by two watchers, are kept apart.

Rust tests consume the checked-in fixture and require neither Python nor network access.
