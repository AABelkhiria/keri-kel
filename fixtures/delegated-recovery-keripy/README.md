# KERI delegated recovery reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-23
- Sources: `src/keri/core/eventing.py` (`Kevery.processEvent`, `Kever.rotate`,
  `Kever.validateDelegation` and `Kever.fetchDelegatingEvent`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. Stored signatures
  are qb64 text, sorted, as keripy's database returns them.

## Why keripy

keripy decides when a delegated rotation (`drt`) may supersede an event its delegate already
accepted, which is how a delegated identifier recovers with its delegator's approval.
`src/kever.rs` and `src/kevery.rs` port it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/delegated_recovery_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/delegated_recovery_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`: each scenario runs keripy's
`Kevery`, unmodified, over its own temporary keripy database, feeds it one message at a time the
way keripy's parser does, and runs `processEscrows` after each. keripy's clock is pinned.

Each step records the exact message bytes, the exception keripy raised if any, and a snapshot of
what keripy then held: each identifier's key state, the signatures and delegating event stored for
each accepted event, the SAIDs of superseded events, and how many events are escrowed.

`rust_outcome` names what the port's `Kevery::process` must return.

## What keripy does, and what its documentation says

`validateDelegation` documents three ways for a delegated rotation to supersede another at the same
sequence number: a delegating event later in the delegator's log, a later seal in the same
delegating event, and a delegating rotation superseding a delegating interaction at the same
number, climbing the delegation chain when none decides. Its code compares the delegating events'
sequence numbers first and then reads an `Ilk` attribute its event objects do not have, so every
case but the first raises `AttributeError` and the rotation is refused. Two scenarios record those
refusals, with the exception keripy raised. The port refuses the same rotations, with
`SupersedingDelegationNotLater`, so that both hold the same events.

keripy also compares against the delegating event of the delegate's latest event, not of the event
superseded. A delegated rotation superseding an interaction that is not the latest event is
therefore compared with an interaction, which has no delegating event: keripy escrows it, then
drops it when a retry finds none.

## Contents

`scenarios` records six scenarios, 42 messages in all:

- `delegated_rotation_supersedes_the_latest_interaction`: a delegated rotation at the latest
  sequence number, an interaction's, supersedes it.
- `later_delegating_event_supersedes`: a delegated rotation anchored by a later delegator event
  supersedes the delegated rotation accepted at its number. The superseded rotation, offered
  again, is taken for another recovery and waits as partially signed.
- `superseding_rotation_found_by_escrow`: the same, the superseding rotation naming no anchoring
  event; escrow processing finds its anchor and lets it supersede.
- `same_delegating_event_does_not_supersede`: a second seal in the same delegating event is refused
  where keripy raises `AttributeError`. The accepted rotation, offered again, is taken for a
  recovery at its own number and waits as partially signed.
- `delegators_recovery_does_not_supersede`: the delegator recovers the interaction anchoring a
  delegated rotation with a rotation anchoring another; that other is refused where keripy raises
  `AttributeError`.
- `earlier_interaction_is_not_superseded`: a delegated rotation superseding an interaction followed
  by another is escrowed, then dropped by escrow processing.

Rust tests consume the checked-in fixture and require neither Python nor network access.
