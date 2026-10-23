# Security Policy

## Supported versions

Security fixes go to the latest `0.x` release. Older `0.x` versions are not patched.

## Reporting a vulnerability

Please don't open a public issue for something you think is exploitable.

Use GitHub's [private vulnerability reporting][gh-pvr] on this repository instead: *Security* →
*Report a vulnerability*.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Useful things to include: the version, something we can run to reproduce it, and what you think the
impact is. Please build the log you report with throwaway keys.

## Threat model

Every event and attachment this crate sees is assumed hostile: it arrives from witnesses, watchers
and controllers that may lie. The crate's job is to accept an event into a log only when the
identifier's keys in force signed it to their threshold, and to say no otherwise.

What it defends:

- An event is accepted only after its SAID, and for an inception its prefix, verify against its
  own bytes, so the fields read are the fields signed.
- Signatures are verified against the keys in force at the event, never against keys the event
  names for itself, except for the inception that establishes them.
- A rotation must reveal keys whose digests the prior establishment event committed to, to that
  event's next-key threshold, so a stolen current key cannot rotate the identifier.
- A refused event leaves the state exactly as it was.
- A delegated event is accepted only once its delegator's log anchors a seal of it.
- A rotation may supersede accepted events only under keripy's recovery rules, as keripy applies
  them, and the events it supersedes are kept, not discarded.
- Any other event that contradicts an accepted one is kept aside as likely duplicitous and never
  accepted.
- A reply, a receipt or a key state notice counts only when its signer's own keys verify it, and a
  reply only when it is newer than the one it replaces.
- Malformed input returns a typed error. Crate-owned code has no `unsafe`, `unwrap`, `expect`,
  panicking macro or indexing that can fail.

What a caller must not assume: that a `Kevery` detects duplicity across the network. It keeps what
it is offered and holds contradictions aside; comparing what several witnesses or watchers report
is `adjudicate`'s job, and only as good as the reports it is given. A store's writes for one message
are not grouped into a transaction; a store that needs them to land together must group them
itself.

## Dependencies

Signature verification and hashing come from `keri-cesr`, and event parsing from `keri-protocol`,
both first-party. `cargo deny` and the resolved graph get reviewed before each release.
