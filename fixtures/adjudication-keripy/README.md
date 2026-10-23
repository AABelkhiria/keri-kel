# KERI key state adjudication reference vectors (keripy)

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/keripy.git`
- Commit: `4ce4cc79e06653f77342be1bf604086b89b1f090` (release `1.3.6`, the latest KERI v1 release)
- Generated: 2026-10-23
- Sources: `src/keri/app/watching.py` (`Adjudicator.adjudicate` and `diffState`)
- Key states are key state records as keripy's `asdict` writes them.

## Why keripy

keripy's `Adjudicator` is how a controller decides, from what its watchers report about an
identifier, whether its local copy of that identifier's log is consistent, behind, or contradicted.
`src/adjudication.rs` ports it.

## Generation

keripy is pinned by commit in `tools/reference-vectors/pyproject.toml` and locked, with hashes, in
`uv.lock` beside it; `uv` installs it and a matching Python. From the repository root:

```bash
uv sync --locked --project tools/reference-vectors
uv run --project tools/reference-vectors python tools/reference-vectors/adjudication_keripy.py --write   # regenerate
uv run --project tools/reference-vectors python tools/reference-vectors/adjudication_keripy.py --check   # verify determinism
```

Set `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or your libsodium location) if pysodium cannot find
libsodium on its own.

## How the outcomes were recorded

`states` holds five key states of one identifier, each derived by keripy's own `Kevery` from the
events it names: `behind` at the inception, `even` at the first interaction and the local state,
`duplicitous` at a different first interaction, `ahead` at a second interaction, and
`ahead_elsewhere` at a different second interaction.

Each case runs keripy's `Adjudicator`, unmodified, over a temporary keripy database holding an
enabled observation of the identifier by each watcher, and the state each watcher reported, if
any, as a kept key state notice. The local identifier is a stand-in holding only that database and
the local state. The case records the cue keripy emits: its `kind`, the watchers it names with
their comparison, reported sequence number and SAID (`named`, sorted), and for an update the
sequence number to catch up to. `kind` is null when keripy emits no cue, and `raised` names the
exception keripy raises instead.

## Contents

`cases` records thirteen cases:

- `all_even`, `silent_watcher`, `no_reports`: consistent, counting only the watchers that reported,
  even when none has.
- `one_behind`: a watcher behind the local state lags.
- `one_duplicitous`, `duplicity_first`: another event at the local sequence number is duplicity,
  which outweighs watchers ahead and behind.
- `all_ahead`, `enough_ahead`: watchers ahead agreeing, at least the threshold of them, are an
  update.
- `too_few_ahead`, `zero_threshold`, `ahead_hides_behind`: watchers ahead agreeing but fewer than
  the threshold, which defaults to every watcher, and zero means the same, decide nothing, even
  when another watcher lags.
- `ahead_on_different_events`: watchers ahead on different events are duplicitous.
- `threshold_above_the_watchers`: a threshold above the watcher count is refused.

Rust tests consume the checked-in fixture and require neither Python nor network access.
