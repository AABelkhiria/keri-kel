# Changelog

> Following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
> and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-30

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
- Key state notices: `Kevery` keeps `/ksn` replies from trusted sources (`NoticeTrust`), signed by
  their source, newer than the one kept before, and consistent with the local log, escrowing those
  awaiting a transferable signer, verified against keripy; unlike keripy, an older notice never
  replaces a newer one.
- End roles and locations: `Kevery` keeps `/end/role/add` and `/end/role/cut` replies signed by
  the controller and `/loc/scheme` replies signed by the endpoint, the latest of each, verified
  against keripy.
- Watcher registrations: `Kevery` keeps `/watcher/{watcher}/add` and `/cut` replies signed by
  the controller, the latest per controller, watcher and observed identifier, and queues the OOBIs
  they give, verified against keripy.
- Queries: `Kevery` answers `logs`, `ksn` and `mbx` queries once its log holds what they ask for,
  replaying events in first-seen order, superseded ones and the delegator's log included, and
  escrows the rest until it can, verified against keripy; `LoggedEvent::first_seen` gives each
  event's first-seen ordinal, and `LoggedEvent::replay` writes it as keripy's log replay does,
  byte for byte.
- Adjudication: `adjudicate` and `Kevery::adjudicate` decide, from what an identifier's watchers
  last reported, whether the local state is consistent, lagging, due an update or contradicted,
  verified against keripy's `Adjudicator`.
- `Record`: writes every record a store keeps, key states, logged and escrowed events, waiting
  receipts, replies and queries, and kept notices, end roles, locations and observations, as
  readable JSON bytes, and reads them back.
- Store traits: `Kevery` keeps its logs, escrows, waiting receipts and replies behind `KelStore`,
  `EscrowStore`, `ReceiptStore` and `ReplyStore`, with `MemoryStore` as the default; a failing
  store is reported as `KelError::Store`.
