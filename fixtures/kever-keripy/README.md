# KERI key event log reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-22
- Sources: `src/keri/core/eventing.py` (`Kever`, `incept`, `rotate`, `interact`, `messagize`),
  `src/keri/core/serdering.py` (`SerderKERI`)
- Binary fields: every `raw_hex` is the lowercase hexadecimal UTF-8 encoding of the exact message
  bytes, event and attachments; `raw` is the same bytes as text and the two are cross-checked on
  load. Every `state_json` is the exact compact JSON of keripy's key state record.

## Why keripy

keripy's `Kever` is the canonical KERI validator, and the one KERIA runs. The pinned signify-ts
reference validates nothing: it trusts KERIA. `src/kever.rs` ports `Kever`.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/kever_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/kever_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

Each scenario offers keripy's `Kever`, unmodified, a sequence of signed events over a temporary
keripy database: the first creates the `Kever`, the rest go to `Kever.update`. Each step records
the exact message bytes and what keripy did: `accepted` with the key state it then held, or the
exception it raised. Steps keripy refuses leave its state as it was, so later steps in the same
scenario build on the last accepted event.

Every key comes from a fixed one-byte seed, so every prefix, SAID and signature is deterministic.
The first-seen time keripy would read from the clock is passed in as a replay datetime, and the
clock itself is pinned to the same instant: keripy's `update` passes no replay datetime when it logs
an interaction, so without the pin an interaction's `dt` would be the time of generation.

Events keripy's own builders refuse to make, an inception with a threshold above its keys for
example, are built by hand with `SerderKERI(sad=…, makify=True)`, so the validator is what refuses
them.

## Contents

`scenarios` records thirteen scenarios, thirty-seven steps in all. Each refused step names the Rust
error category the port must return for it.

- `single_key_lifecycle`: inception, interaction, rotation, interaction, rotation, then one refused
  event per ordering rule: a wrong prior digest, an interaction and a rotation skipping a sequence
  number, a stale rotation, an interaction signed by a stranger, a rotation to keys the prior event
  did not commit to, and an event of another identifier.
- `two_of_three_partially_signed` and `two_of_three`: three keys with a threshold of two, signed
  once and then twice.
- `weighted_partial_rotation`: weighted thresholds of halves. A rotation exposing one committed key
  meets the new threshold with two fresh keys but not the prior next-key threshold; one exposing
  two committed keys meets both.
- `witnessed`: three witnesses with a threshold of two, witnessed once and then twice; a rotation
  cutting one witness and adding another; an interaction witnessed by the new set; and three
  refused rotations: cutting a former witness, adding a current one, and a witness threshold above
  the set.
- `establishment_only`: `EO` and `DND`; an interaction is refused and a rotation accepted.
- `abandoned`: a rotation committing to no next keys, after which an interaction is refused.
- `non_transferable`: a basic non-transferable identifier, which takes no event after inception.
- Five inceptions keripy's validator refuses: a threshold above the keys, a duplicate witness, a
  witness threshold above the set or without witnesses, and a non-zero sequence number.

`divergence_recovery_rotation` records the one behaviour the port does not follow yet: keripy
accepts a rotation that replaces an interaction already accepted at its sequence number, a recovery
rotation, and the port refuses it with `RecoveryUnsupported` until recovery is ported with its own
fixtures. Generating these vectors also showed that keripy skips every witness-change check on a
recovery rotation.

Rust tests consume the checked-in fixture and require neither Python nor network access.
