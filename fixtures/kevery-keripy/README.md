# KERI log processing reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`Kevery.processEvent`, `processReceipt`,
  `processAttachedReceiptCouples`, `processEscrows` and the partially signed, partially witnessed
  and unverified receipt escrows)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes; `raw` is the same bytes as text and the two are cross-checked on load. Stored signatures
  are qb64 text, sorted, as keripy's database returns them; a stored receipt couple is the
  receiptor's key followed by its signature.

## Why keripy

keripy's `Kevery` routes every message KERIA and keripy witnesses receive. `src/kevery.rs` ports
it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/kevery_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/kevery_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

Each scenario runs keripy's `Kevery`, unmodified, over its own temporary keripy database, and feeds
it messages the way keripy's parser does: a key event to `processEvent`, then any attached receipt
couples to `processAttachedReceiptCouples`; a receipt to `processReceipt`. After every message,
`processEscrows` runs. Each step records the exact message bytes, the exception keripy raised if
any, and a snapshot of what keripy then held: each identifier's key state, the controller
signatures, witness signatures and receipt couples stored for each accepted event, and how many
events and receipt signatures are waiting.

keripy's clock is pinned, both the time it stamps as first seen and the time it measures escrow
ages against, so the snapshots are deterministic and no escrow times out.

`rust_outcome` names what the port's `Kevery::process` must return for the message: an outcome, or
an error category. keripy signals an escrowed message by raising, so `MissingSignatureError`,
`MissingWitnessSignatureError` and `UnverifiedReceiptError` correspond to the port's escrowed
outcomes.

## Contents

`scenarios` records four scenarios, fifteen messages in all:

- `receipts_complete_a_witnessed_inception`: an inception needing two of three witnesses arrives
  with none; a witness's indexed signature and then another witness's receipt couple arrive as
  receipts, are matched to the waiting event, and the second completes it.
- `signatures_gathered_across_offers`: a two-of-three inception offered twice with one signature
  each time; the escrow holds both and accepts it.
- `receipts_and_duplicates_for_accepted_events`: an accepted inception gains a witness signature
  by receipt, a stranger's receipt couple, and a second controller signature when offered again; a
  receipt naming another event at the same number is stale; a different interaction at an accepted
  number is likely duplicitous.
- `receipt_completes_a_rotation_changing_witnesses`: a rotation that cuts one witness and adds
  another waits for its new witness set, and a receipt indexed into that new set completes it.

`divergence_attached_witness_couple` records the one behaviour the port does not follow. keripy's
`processAttachedReceiptCouples` compares a couple's key, a string, against a list of prefix objects,
which never matches, so a witness's couple attached to an event is stored as a plain receipt and
does not count toward the witness threshold. The port stores it as that witness's signature, as
keripy's `processReceipt` does for the same couple arriving as a receipt.

Rust tests consume the checked-in fixture and require neither Python nor network access.
