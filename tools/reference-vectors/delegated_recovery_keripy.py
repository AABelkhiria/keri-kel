"""Generates and checks delegated recovery vectors from the pinned keripy.

``src/kevery.rs`` ports keripy's rules for a delegated rotation (``drt``) that supersedes an event
already accepted: ``Kever.rotate``'s recovery branch and the superseding part of
``Kever.validateDelegation``. Each scenario offers keripy's ``Kevery``, unmodified, a delegator's and
a delegate's events, the way keripy's parser would, processes escrows after each, and records what
keripy then holds, superseded events included, with ``kevery_keripy.Scenario``. keripy's clock is
pinned. keripy is pinned in ``pyproject.toml`` and ``uv.lock`` beside this file; run from the
repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/delegated_recovery_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import datetime
import json
import pathlib
import sys

from keri.core import eventing
from keri.help import helping

from delegation_keripy import delegator, seal
from kevery_keripy import STAMP, Scenario, digest, signer
from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-23"


class Delegate:
    """A single-key delegate: its signers in rotation order and its delegated inception."""

    def __init__(self, seed, delpre):
        self.keys = [signer(seed + index) for index in range(5)]
        self.dip = eventing.delcept(keys=[self.keys[0].verfer.qb64], delpre=delpre, ndigs=[digest(self.keys[1])])

    def drt(self, sn, prior, key):
        """A delegated rotation at `sn` following `prior`, to `self.keys[key]`."""
        return eventing.deltate(pre=self.dip.pre, keys=[self.keys[key].verfer.qb64], dig=prior.said, sn=sn,
                                ndigs=[digest(self.keys[key + 1])])


def signed(scenario, label, serder, key, expect, source=None):
    return scenario.event(label, serder, expect, sigers=[key.sign(ser=serder.raw, index=0)], source=source)


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    scenarios = []

    # A delegated rotation superseding the latest interaction.
    d, dicp = delegator(1)
    e = Delegate(10, dicp.pre)
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(e.dip)])
    ixn = eventing.interact(pre=e.dip.pre, dig=e.dip.said, sn=1)
    drt = e.drt(1, e.dip, 1)
    reanchor = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(drt)])
    scenario = Scenario("delegated_rotation_supersedes_the_latest_interaction",
                        "A delegated rotation at the delegate's latest sequence number, an interaction's,"
                        " follows the inception and is anchored by its delegator; it supersedes the"
                        " interaction.", [dicp.pre, e.dip.pre])
    signed(scenario, "delegator_inception", dicp, d, "Accepted")
    signed(scenario, "delegator_anchors_the_inception", anchor, d, "Accepted")
    signed(scenario, "delegated_inception", e.dip, e.keys[0], "Accepted", source=(1, anchor.said))
    signed(scenario, "delegate_interaction", ixn, e.keys[0], "Accepted")
    signed(scenario, "delegator_anchors_the_rotation", reanchor, d, "Accepted")
    signed(scenario, "superseding_delegated_rotation", drt, e.keys[1], "Accepted", source=(2, reanchor.said))
    scenarios.append(scenario.record())

    # A delegated rotation superseding a delegated rotation, anchored later.
    d, dicp = delegator(20)
    e = Delegate(30, dicp.pre)
    first, second = e.drt(1, e.dip, 1), e.drt(1, e.dip, 2)
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(e.dip)])
    anchor_first = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(first)])
    anchor_second = eventing.interact(pre=dicp.pre, dig=anchor_first.said, sn=3, data=[seal(second)])
    scenario = Scenario("later_delegating_event_supersedes",
                        "A delegated rotation is accepted. Another at the same sequence number, signed with the"
                        " key the first committed to and anchored by a later event of the delegator,"
                        " supersedes it. Offered again, the first is treated as another recovery at that"
                        " number; its key exposes none of the next keys now committed to, so it waits as"
                        " partially signed.",
                        [dicp.pre, e.dip.pre])
    signed(scenario, "delegator_inception", dicp, d, "Accepted")
    signed(scenario, "delegator_anchors_the_inception", anchor, d, "Accepted")
    signed(scenario, "delegated_inception", e.dip, e.keys[0], "Accepted", source=(1, anchor.said))
    signed(scenario, "delegator_anchors_the_first_rotation", anchor_first, d, "Accepted")
    signed(scenario, "first_delegated_rotation", first, e.keys[1], "Accepted", source=(2, anchor_first.said))
    signed(scenario, "delegator_anchors_the_second_rotation", anchor_second, d, "Accepted")
    signed(scenario, "second_delegated_rotation", second, e.keys[2], "Accepted", source=(3, anchor_second.said))
    signed(scenario, "first_delegated_rotation_again", first, e.keys[1], "Escrowed:PartiallySigned",
           source=(2, anchor_first.said))
    scenarios.append(scenario.record())

    # The same, the superseding rotation naming no anchoring event.
    d, dicp = delegator(40)
    e = Delegate(50, dicp.pre)
    first, second = e.drt(1, e.dip, 1), e.drt(1, e.dip, 2)
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(e.dip)])
    anchor_first = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(first)])
    anchor_second = eventing.interact(pre=dicp.pre, dig=anchor_first.said, sn=3, data=[seal(second)])
    scenario = Scenario("superseding_rotation_found_by_escrow",
                        "A superseding delegated rotation naming no anchoring event waits, and escrow"
                        " processing finds its anchor in the delegator's log and lets it supersede.",
                        [dicp.pre, e.dip.pre])
    signed(scenario, "delegator_inception", dicp, d, "Accepted")
    signed(scenario, "delegator_anchors_the_inception", anchor, d, "Accepted")
    signed(scenario, "delegated_inception", e.dip, e.keys[0], "Accepted", source=(1, anchor.said))
    signed(scenario, "delegator_anchors_the_first_rotation", anchor_first, d, "Accepted")
    signed(scenario, "first_delegated_rotation", first, e.keys[1], "Accepted", source=(2, anchor_first.said))
    signed(scenario, "delegator_anchors_the_second_rotation", anchor_second, d, "Accepted")
    signed(scenario, "second_delegated_rotation_without_source", second, e.keys[2], "Escrowed:PartiallyDelegated")
    scenarios.append(scenario.record())

    # The same delegating event, a later seal.
    d, dicp = delegator(60)
    e = Delegate(70, dicp.pre)
    first, second = e.drt(1, e.dip, 1), e.drt(1, e.dip, 2)
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(e.dip)])
    both = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(first), seal(second)])
    scenario = Scenario("same_delegating_event_does_not_supersede",
                        "One delegator event anchors two delegated rotations at the same sequence number, the"
                        " second seal after the first. keripy's documented rules let the later seal"
                        " supersede, but its code raises `AttributeError` comparing the two delegating"
                        " events before reaching that rule, so the second rotation is refused. The first,"
                        " offered again, is treated as a recovery at its own number rather than a duplicate;"
                        " its key exposes none of the next keys it committed to, so it waits as partially"
                        " signed.", [dicp.pre, e.dip.pre])
    signed(scenario, "delegator_inception", dicp, d, "Accepted")
    signed(scenario, "delegator_anchors_the_inception", anchor, d, "Accepted")
    signed(scenario, "delegated_inception", e.dip, e.keys[0], "Accepted", source=(1, anchor.said))
    signed(scenario, "delegator_anchors_both_rotations", both, d, "Accepted")
    signed(scenario, "first_delegated_rotation", first, e.keys[1], "Accepted", source=(2, both.said))
    signed(scenario, "second_delegated_rotation", second, e.keys[2], "SupersedingDelegationNotLater",
           source=(2, both.said))
    signed(scenario, "first_delegated_rotation_again", first, e.keys[1], "Escrowed:PartiallySigned",
           source=(2, both.said))
    scenarios.append(scenario.record())

    # A delegator's own recovery, anchoring the superseding rotation.
    dk = [signer(80), signer(81), signer(82)]
    dicp = eventing.incept(keys=[dk[0].verfer.qb64], ndigs=[digest(dk[1])], code="E")
    e = Delegate(90, dicp.pre)
    first, second = e.drt(1, e.dip, 1), e.drt(1, e.dip, 2)
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(e.dip)])
    anchor_first = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(first)])
    recovery = eventing.rotate(pre=dicp.pre, keys=[dk[1].verfer.qb64], dig=anchor.said, sn=2,
                               ndigs=[digest(dk[2])], data=[seal(second)])
    scenario = Scenario("delegators_recovery_does_not_supersede",
                        "The delegator recovers the interaction that anchored a delegated rotation with a"
                        " rotation anchoring another at the same sequence number. keripy's documented rules"
                        " let a delegating rotation supersede a delegating interaction at the same number,"
                        " but its code raises `AttributeError` before reaching that rule, so the second"
                        " delegated rotation is refused.", [dicp.pre, e.dip.pre])
    signed(scenario, "delegator_inception", dicp, dk[0], "Accepted")
    signed(scenario, "delegator_anchors_the_inception", anchor, dk[0], "Accepted")
    signed(scenario, "delegated_inception", e.dip, e.keys[0], "Accepted", source=(1, anchor.said))
    signed(scenario, "delegator_anchors_the_first_rotation", anchor_first, dk[0], "Accepted")
    signed(scenario, "first_delegated_rotation", first, e.keys[1], "Accepted", source=(2, anchor_first.said))
    signed(scenario, "delegator_recovers_anchoring_the_second", recovery, dk[1], "Accepted")
    signed(scenario, "second_delegated_rotation", second, e.keys[2], "SupersedingDelegationNotLater",
           source=(2, recovery.said))
    scenarios.append(scenario.record())

    # A delegated rotation superseding an interaction that is not the latest event.
    d, dicp = delegator(100)
    e = Delegate(110, dicp.pre)
    ixn1 = eventing.interact(pre=e.dip.pre, dig=e.dip.said, sn=1)
    ixn2 = eventing.interact(pre=e.dip.pre, dig=ixn1.said, sn=2)
    drt = e.drt(1, e.dip, 1)
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(e.dip)])
    reanchor = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(drt)])
    scenario = Scenario("earlier_interaction_is_not_superseded",
                        "A delegated rotation would supersede an interaction followed by another. keripy"
                        " looks for the delegating event of the delegate's latest event, an interaction that"
                        " has none: it escrows the rotation, then drops it once escrow processing finds"
                        " none.", [dicp.pre, e.dip.pre])
    signed(scenario, "delegator_inception", dicp, d, "Accepted")
    signed(scenario, "delegator_anchors_the_inception", anchor, d, "Accepted")
    signed(scenario, "delegated_inception", e.dip, e.keys[0], "Accepted", source=(1, anchor.said))
    signed(scenario, "first_interaction", ixn1, e.keys[0], "Accepted")
    signed(scenario, "second_interaction", ixn2, e.keys[0], "Accepted")
    signed(scenario, "delegator_anchors_the_rotation", reanchor, d, "Accepted")
    signed(scenario, "superseding_delegated_rotation", drt, e.keys[1], "Escrowed:PartiallyDelegated",
           source=(2, reanchor.said))
    scenarios.append(scenario.record())

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py"],
        "now": STAMP,
        "scenarios": scenarios,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "delegated-recovery-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("delegated-recovery-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
