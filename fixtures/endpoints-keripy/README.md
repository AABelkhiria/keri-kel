# KERI end role and location reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-23
- Sources: `src/keri/core/eventing.py` (`Kevery.processReplyEndRole`, `processReplyLocScheme`,
  `updateEnd` and `updateLoc`) and `src/keri/core/routing.py` (`Revery.processReply`,
  `acceptReply`, `escrowReply` and `processEscrowReply`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load.

## Why keripy

End role replies (`/end/role/add`, `/end/role/cut`) say which endpoint serves an identifier in which
role, witness, watcher or mailbox among them; location replies (`/loc/scheme`) give an endpoint's
URL for a scheme. Every client resolving an OOBI, and a watcher checking that a querier holds a
watcher role, relies on them. keripy's `Kevery` decides which to keep, and `src/endpoint.rs` ports
it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/endpoints_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/endpoints_keripy.py --check   # verify determinism
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
what keripy then held: identifiers' key states and events, the end roles kept (from keripy's `ends`
table, whether each is allowed), the locations kept (from its `locs` table), and how many replies
wait in its reply escrow.

`rust_outcome` names what the port's `Kevery::process` must return. keripy raises
`UnverifiedReplyError` both when a reply waits and when no signature establishes it, so
`rust_outcome` says which; it raises a plain `ValidationError` for a role or scheme it does not
know, which the port reports as an invalid reply.

## Contents

`scenarios` records four scenarios, 17 messages in all:

- `role_granted_and_withdrawn`: a controller grants a watcher role and withdraws it in a later
  reply; the same withdrawal offered again is kept again, as keripy's end role handler treats a
  reply identical to the one kept; the grant offered again, being older, is not; a mailbox role
  for the same endpoint is kept apart.
- `grants_keripy_refuses`: a grant signed by the endpoint rather than the controller is not kept,
  and one naming an unknown role is refused.
- `grant_before_the_controller`: a grant waits in the reply escrow until the controller's
  inception is accepted.
- `endpoint_locations`: an endpoint's newer HTTP location replaces the older one; the newer one
  offered again is not newer than itself, as keripy's location handler has no exception for a
  reply identical to the one kept; a TCP location is kept apart; a location signed by someone else
  is not kept, and one whose URL does not use its scheme is refused.

Rust tests consume the checked-in fixture and require neither Python nor network access.
