"""Generates and checks out-of-order and likely-duplicitous vectors from the pinned keripy.

``src/kevery.rs`` ports keripy's out-of-order and likely-duplicitous escrows: an event that comes
before the events it follows waits for them, and an event that contradicts one already accepted is
kept aside. Each scenario offers keripy's ``Kevery``, unmodified, messages in some order, the way
keripy's parser would, processes escrows after each, and records what keripy then holds, with
``kevery_keripy.Scenario``. keripy's clock is pinned. keripy is pinned in ``pyproject.toml`` and
``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/out_of_order_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import datetime
import json
import pathlib
import sys

from keri.core import eventing
from keri.core.coring import MtrDex
from keri.help import helping

from delegation_keripy import delegator, seal
from kevery_keripy import STAMP, Scenario, digest, signer
from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    scenarios = []

    # A log arriving backwards.
    a0, a1, a2 = signer(200), signer(201), signer(202)
    icp = eventing.incept(keys=[a0.verfer.qb64], ndigs=[digest(a1)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    rot = eventing.rotate(pre=icp.pre, keys=[a1.verfer.qb64], dig=ixn2.said, sn=3, ndigs=[digest(a2)])
    scenarios.append(Scenario("log_in_reverse",
                              "Every event of a log arrives before the one it follows. Each waits; the inception"
                              " is accepted, and one escrow pass accepts the rest in sequence order.", [icp.pre])
                     .event("rotation", rot, "Escrowed:OutOfOrder", sigers=[a1.sign(ser=rot.raw, index=0)])
                     .event("second_interaction", ixn2, "Escrowed:OutOfOrder",
                            sigers=[a0.sign(ser=ixn2.raw, index=0)])
                     .event("first_interaction", ixn1, "Escrowed:OutOfOrder",
                            sigers=[a0.sign(ser=ixn1.raw, index=0)])
                     .event("inception", icp, "Accepted", sigers=[a0.sign(ser=icp.raw, index=0)])
                     .record())

    # A gap in a known log.
    b0, b1 = signer(210), signer(211)
    icp = eventing.incept(keys=[b0.verfer.qb64], ndigs=[digest(b1)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    scenarios.append(Scenario("gap_in_a_known_log",
                              "An accepted log receives the event after next, which waits until the next one is"
                              " accepted.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[b0.sign(ser=icp.raw, index=0)])
                     .event("second_interaction", ixn2, "Escrowed:OutOfOrder",
                            sigers=[b0.sign(ser=ixn2.raw, index=0)])
                     .event("first_interaction", ixn1, "Accepted", sigers=[b0.sign(ser=ixn1.raw, index=0)])
                     .record())

    # Out of order and short of signatures.
    m = [signer(220), signer(221)]
    icp = eventing.incept(keys=[key.verfer.qb64 for key in m], isith="2", ndigs=[digest(signer(222))],
                          code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    both = lambda serder: [key.sign(ser=serder.raw, index=index) for index, key in enumerate(m)]  # noqa: E731
    scenarios.append(Scenario("out_of_order_and_partially_signed",
                              "A two-of-two interaction arrives early with one signature. Once the event before"
                              " it is accepted, it moves to the partially signed escrow, and its second"
                              " signature completes it.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=both(icp))
                     .event("second_interaction_with_one_signature", ixn2, "Escrowed:OutOfOrder",
                            sigers=[m[0].sign(ser=ixn2.raw, index=0)])
                     .event("first_interaction", ixn1, "Accepted", sigers=both(ixn1))
                     .event("second_interaction_with_the_other_signature", ixn2, "Escrowed:PartiallySigned",
                            sigers=[m[1].sign(ser=ixn2.raw, index=1)])
                     .record())

    # Escrowed without verification, dropped once verified.
    c0, c1, stranger = signer(230), signer(231), signer(239)
    icp = eventing.incept(keys=[c0.verfer.qb64], ndigs=[digest(c1)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    scenarios.append(Scenario("out_of_order_with_a_bad_signature",
                              "An early event signed by a key that is not the identifier's waits, since nothing"
                              " can be verified before the events it follows; once they are accepted its"
                              " signature fails and it is dropped.", [icp.pre])
                     .event("second_interaction_badly_signed", ixn2, "Escrowed:OutOfOrder",
                            sigers=[stranger.sign(ser=ixn2.raw, index=0)])
                     .event("inception", icp, "Accepted", sigers=[c0.sign(ser=icp.raw, index=0)])
                     .event("first_interaction", ixn1, "Accepted", sigers=[c0.sign(ser=ixn1.raw, index=0)])
                     .record())

    # An early delegated rotation.
    d, dicp = delegator(240)
    e0, e1, e2 = signer(250), signer(251), signer(252)
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)])
    ixn = eventing.interact(pre=dip.pre, dig=dip.said, sn=1)
    drt = eventing.deltate(pre=dip.pre, keys=[e1.verfer.qb64], dig=ixn.said, sn=2, ndigs=[digest(e2)])
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(dip)])
    reanchor = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(drt)])
    scenarios.append(Scenario("out_of_order_delegated_rotation",
                              "A delegated rotation naming its anchoring event arrives before the interaction it"
                              " follows. When retried, keripy offers it without the seal source couple, so it"
                              " moves to the partially delegated escrow, where the anchor is found by walking"
                              " the delegator's log.", [dicp.pre, dip.pre])
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .event("delegated_inception", dip, "Accepted", sigers=[e0.sign(ser=dip.raw, index=0)],
                            source=(1, anchor.said))
                     .event("delegator_anchors_the_rotation", reanchor, "Accepted",
                            sigers=[d.sign(ser=reanchor.raw, index=0)])
                     .event("delegated_rotation", drt, "Escrowed:OutOfOrder", sigers=[e1.sign(ser=drt.raw, index=0)],
                            source=(2, reanchor.said))
                     .event("delegate_interaction", ixn, "Accepted", sigers=[e0.sign(ser=ixn.raw, index=0)])
                     .record())

    # Contradictions of accepted events.
    f0, f1, f2 = signer(190), signer(191), signer(192)
    icp = eventing.incept(keys=[f0.verfer.qb64], ndigs=[digest(f1)])
    other_icp = eventing.incept(keys=[f0.verfer.qb64], ndigs=[digest(f2)])
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    other_ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=[{"i": icp.pre}])
    scenarios.append(Scenario("likely_duplicitous",
                              "A basic prefix is its key, so a second inception committing to other next keys"
                              " has the same prefix and contradicts the first; a second interaction at an"
                              " accepted number does too. Both are kept aside, once each however often they are"
                              " offered, and never accepted.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[f0.sign(ser=icp.raw, index=0)])
                     .event("interaction", ixn, "Accepted", sigers=[f0.sign(ser=ixn.raw, index=0)])
                     .event("another_inception", other_icp, "Escrowed:LikelyDuplicitous",
                            sigers=[f0.sign(ser=other_icp.raw, index=0)])
                     .event("another_interaction", other_ixn, "Escrowed:LikelyDuplicitous",
                            sigers=[f0.sign(ser=other_ixn.raw, index=0)])
                     .event("another_interaction_again", other_ixn, "Escrowed:LikelyDuplicitous",
                            sigers=[f0.sign(ser=other_ixn.raw, index=0)])
                     .record())

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

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "out-of-order-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("out-of-order-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
