# KERI delegation reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`Kever.valSigsWigsDel`, `Kever.validateDelegation`,
  `Kevery.processEvent`, `escrowPDEvent` and `processEscrowPartialDels`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. Stored signatures
  are qb64 text, sorted, as keripy's database returns them.

## Why keripy

keripy's `Kever` and `Kevery` decide whether a delegated identifier's events are approved by its
delegator for KERIA and keripy witnesses. `src/kever.rs` and `src/kevery.rs` port them.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/delegation_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/delegation_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`: each scenario runs keripy's
`Kevery`, unmodified, over its own temporary keripy database, feeds it one message at a time the
way keripy's parser does, and runs `processEscrows` after each. A delegated event may carry a seal
source couple (`-G`) naming its delegating event; it is attached to the message bytes and handed to
`processEvent` as keripy's parser hands it. keripy's clock is pinned.

Each step records the exact message bytes, the exception keripy raised if any, and a snapshot of
what keripy then held: each identifier's key state, the signatures stored for each accepted event,
the delegating event stored for each accepted delegated event (`delegation`, from keripy's `aess`
table), and how many events are escrowed, the partially delegated escrow included.

`rust_outcome` names what the port's `Kevery::process` must return. keripy signals an escrowed
event by raising, so `MissingDelegationError` corresponds to the port's partially delegated
outcome. keripy raises a plain `ValidationError` for each refusal recorded here; `rust_outcome`
names the port's error for it.

## Contents

`scenarios` records seven scenarios, 27 messages in all:

- `anchored_delegation`: the delegator anchors seals of a delegated inception and, later, a
  delegated rotation before each arrives naming its anchoring event; both are accepted. An
  interaction needs no anchor, and a plain rotation (`rot`) of the delegated identifier is
  refused.
- `delegation_waits_for_its_anchor`: a delegated inception naming no anchoring event waits until
  the delegator anchors it, and escrow processing finds the anchor by walking the delegator's log.
- `delegate_before_its_delegator`: a delegated inception arrives before anything of its delegator
  and waits through the delegator's inception until its anchoring event is accepted.
- `wrong_source_is_repaired`: a seal source couple naming the delegator's inception is refused,
  since an inception cannot anchor; one naming an interaction without the seal is discarded, and
  escrow processing finds the real anchor and stores it instead.
- `delegator_forbids_delegation`: a delegator configured with `DND` cannot approve a delegated
  inception, even one it anchors.
- `witnessed_delegate`: a witnessed delegated inception waits for its witnesses first, keeping the
  seal source couple it named, and a witness receipt completes it.
- `delegated_rotation_of_an_undelegated_identifier`: keripy validates a delegation only for an
  identifier with a delegator, so it accepts a `drt` of an undelegated identifier as an ordinary
  rotation. The port does the same.

A rotation superseding an accepted one, which a delegated identifier may use to recover, is not
recorded here; the port refuses it until recovery is ported.

Rust tests consume the checked-in fixture and require neither Python nor network access.
