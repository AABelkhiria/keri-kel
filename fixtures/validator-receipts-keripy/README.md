# KERI validator receipt reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-23
- Sources: `src/keri/core/eventing.py` (`Kevery.processReceipt`,
  `processAttachedReceiptQuadruples`, `escrowTRGroups`, `escrowTReceipts`, `escrowTRQuadruple` and
  `processEscrowUnverTrans`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. Stored signatures
  are qb64 text, sorted, as keripy's database returns them; a stored validator receipt is the
  validator's prefix, its establishment event's sequence number and SAID, and the indexed
  signature.

## Why keripy

A validator is a transferable identifier that receipts others' events; watchers are one kind.
keripy's `Kevery` decides which of their signatures it stores, and `src/kevery.rs` ports it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/validator_receipts_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/validator_receipts_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

The generator reuses the scenario runner of `kevery_keripy.py`: each scenario runs keripy's
`Kevery`, unmodified, over its own temporary keripy database, feeds it one message at a time the
way keripy's parser does, and runs `processEscrows` after each. keripy's clock is pinned.

A validator's receipt carries an indexed signature group (`-F`) after the receipt, written by
keripy's `messagize`; quadruples attached to an event (`-D`) are appended to the event's
attachments. keripy's parser hands quadruples to `processAttachedReceiptQuadruples` only once the
event is accepted, and what that raises does not change what became of the event, so it is
recorded apart, under `keripy.attachments`.

Each step records the exact message bytes, the exception keripy raised if any, and a snapshot of
what keripy then held: each identifier's key state, the signatures and validator receipts stored
for each accepted event, and how many events and receipt signatures are waiting, the unverified
transferable receipt escrow included.

`rust_outcome` names what the port's `Kevery::process` must return. keripy signals an escrowed
receipt by raising, so `UnverifiedReceiptError` and `UnverifiedTransferableReceiptError` correspond
to the port's escrowed outcomes; it raises a plain `ValidationError` for each refusal, and
`rust_outcome` names the port's error for it.

## Contents

`scenarios` records six scenarios, 27 messages in all:

- `validator_receipts_an_accepted_event`: a validator's receipt is stored once, however often it
  arrives.
- `receipt_before_both_events`: a receipt arriving before the receipted event and the validator's
  inception waits for both.
- `receipt_before_the_validator`: a receipt of an accepted event waits for the validator's
  inception.
- `receipts_keripy_refuses_or_skips`: receipts naming another event than the validator's at that
  number, an interaction, or a key position past the validator's keys are refused; one whose
  signature fails is skipped without error.
- `receipts_from_a_rotated_validator`: a validator receipts with the keys of its inception and,
  naming its rotation, with its rotated keys; both are stored.
- `quadruples_attached_to_events`: quadruples from a known validator are stored, one from a
  validator not seen yet waits for its inception, and one whose signature fails is dropped, while
  each event is accepted.

Rust tests consume the checked-in fixture and require neither Python nor network access.
