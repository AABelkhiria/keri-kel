# Changelog

> Following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
> and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Kever`: accepts inceptions, rotations and interactions of undelegated identifiers into a key
  state, with numeric and weighted thresholds, partial rotations, attached witness signatures,
  witness changes and the `EO` and `DND` traits, verified against keripy's `Kever`.
- `KeyEventFields`: reads a key event, verifying its SAID and, for an inception, its prefix.
- `KelError`, with `escrow` saying when waiting for more signatures could help.
