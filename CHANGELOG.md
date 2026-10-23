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
- `Kevery`: routes events and receipts across many identifiers' logs, stores the verified
  signatures of every accepted event, and escrows partially signed and partially witnessed events
  and early receipts until they complete, verified against keripy's `Kevery`.
- Delegated identifiers: `Kevery` accepts a delegated inception or rotation once its delegator's
  log anchors a seal of it, checks the seal source couple it names, escrows it as partially
  delegated until then, and stores the delegating event with it, verified against keripy.
- Out-of-order and likely-duplicitous escrows: `Kevery` keeps an event that arrives before the
  events it follows until they are accepted, keeps an event contradicting an accepted one aside,
  and retries escrows in keripy's order, verified against keripy.
- Recovery rotations: a rotation following an event accepted since the latest establishment event
  supersedes the events after it; `Kevery::superseded` keeps them, verified against keripy.
- Delegated recovery: a delegated rotation supersedes the latest delegated rotation when its
  delegating event is later in the delegator's log, or the latest event when that is an
  interaction at its number, and every other delegated supersession is refused, as keripy does.
- Validator receipts: `Kevery` verifies receipts from transferable identifiers, in receipts and
  attached to events, against the validator's named establishment event, stores them as
  `ValidatorReceipt`s, and escrows them until the validator's event is accepted, verified against
  keripy.
- Store traits: `Kevery` keeps its logs, escrows and waiting receipts behind `KelStore`,
  `EscrowStore` and `ReceiptStore`, with `MemoryStore` as the default; a failing store is reported
  as `KelError::Store`.
