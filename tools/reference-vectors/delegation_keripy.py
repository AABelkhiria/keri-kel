"""Generates and checks delegation vectors from the pinned keripy.

``src/kevery.rs`` and ``src/kever.rs`` port keripy's validation of delegated identifiers: a
delegated inception (``dip``) or rotation (``drt``) is accepted only once its delegator's log holds
an event anchoring a seal of it. Each scenario offers keripy's ``Kevery``, unmodified, the
delegator's and the delegate's events in some order, the way keripy's parser would, processes
escrows after each, and records what keripy then holds, with ``kevery_keripy.Scenario``. keripy's
clock is pinned. keripy is pinned in ``pyproject.toml`` and ``uv.lock`` beside this file; run from
the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/delegation_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import datetime
import json
import pathlib
import sys

from keri.core import eventing
from keri.core.coring import MtrDex
from keri.help import helping

from kevery_keripy import STAMP, Scenario, digest, signer
from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"


def seal(serder):
    """The event seal a delegator anchors to approve a delegated event."""
    return {"i": serder.pre, "s": serder.snh, "d": serder.said}


def delegator(seed, *, wits=(), toad=0, cnfg=None):
    """A single-key delegator: its signer, its inception, and the signer of its next key."""
    key, nxt = signer(seed), signer(seed + 1)
    icp = eventing.incept(keys=[key.verfer.qb64], ndigs=[digest(nxt)], wits=list(wits), toad=toad, cnfg=cnfg,
                          code=MtrDex.Blake3_256)
    return key, icp


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    ws = [signer(30 + index, transferable=False) for index in range(2)]
    scenarios = []

    # A delegate whose every establishment event is anchored before it arrives.
    d, dicp = delegator(60)
    e0, e1, e2 = signer(70), signer(71), signer(72)
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)])
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(dip)])
    drt = eventing.deltate(pre=dip.pre, keys=[e1.verfer.qb64], dig=dip.said, sn=1, ndigs=[digest(e2)])
    reanchor = eventing.interact(pre=dicp.pre, dig=anchor.said, sn=2, data=[seal(drt)])
    ixn = eventing.interact(pre=dip.pre, dig=drt.said, sn=2)
    rot = eventing.rotate(pre=dip.pre, keys=[e2.verfer.qb64], dig=ixn.said, sn=3, ndigs=[digest(signer(73))])
    scenarios.append(Scenario("anchored_delegation",
                              "The delegator anchors a seal of the delegated inception, then of the delegated"
                              " rotation, before each arrives naming its anchoring event. Both are accepted,"
                              " with the anchoring event stored as their source. An interaction needs no"
                              " anchor, and a plain rotation of a delegated identifier is refused.",
                              [dicp.pre, dip.pre])
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .event("delegated_inception", dip, "Accepted", sigers=[e0.sign(ser=dip.raw, index=0)],
                            source=(1, anchor.said))
                     .event("delegator_anchors_the_rotation", reanchor, "Accepted",
                            sigers=[d.sign(ser=reanchor.raw, index=0)])
                     .event("delegated_rotation", drt, "Accepted", sigers=[e1.sign(ser=drt.raw, index=0)],
                            source=(2, reanchor.said))
                     .event("delegate_interaction", ixn, "Accepted", sigers=[e1.sign(ser=ixn.raw, index=0)])
                     .event("plain_rotation_of_a_delegate", rot, "UndelegatedRotation",
                            sigers=[e2.sign(ser=rot.raw, index=0)])
                     .record())

    # A delegated inception waiting for its anchor.
    d, dicp = delegator(80)
    e0, e1 = signer(90), signer(91)
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)])
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(dip)])
    scenarios.append(Scenario("delegation_waits_for_its_anchor",
                              "A delegated inception naming no anchoring event arrives before the delegator"
                              " anchors it, and waits. Once the anchoring event is accepted, escrow processing"
                              " finds it by walking the delegator's log and accepts the delegate.",
                              [dicp.pre, dip.pre])
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegated_inception_without_source", dip, "Escrowed:PartiallyDelegated",
                            sigers=[e0.sign(ser=dip.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .record())

    # A delegated inception arriving before its delegator.
    d, dicp = delegator(100)
    e0, e1 = signer(110), signer(111)
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)])
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(dip)])
    scenarios.append(Scenario("delegate_before_its_delegator",
                              "A delegated inception naming its anchoring event arrives before anything of its"
                              " delegator, and waits; it keeps waiting once the delegator's inception is"
                              " accepted, and is accepted with the anchoring event.", [dicp.pre, dip.pre])
                     .event("delegated_inception", dip, "Escrowed:PartiallyDelegated",
                            sigers=[e0.sign(ser=dip.raw, index=0)], source=(1, anchor.said))
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .record())

    # Source couples naming events without the seal.
    d, dicp = delegator(120)
    e0, e1 = signer(130), signer(131)
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)])
    unrelated = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1)
    anchor = eventing.interact(pre=dicp.pre, dig=unrelated.said, sn=2, data=[seal(dip)])
    scenarios.append(Scenario("wrong_source_is_repaired",
                              "A delegated inception naming the delegator's inception as its anchoring event is"
                              " refused: an inception cannot anchor. Offered again naming an interaction that"
                              " holds no seal of it, keripy discards that source and escrows the event, and"
                              " escrow processing finds the real anchoring event and stores it as the source.",
                              [dicp.pre, dip.pre])
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegator_interaction", unrelated, "Accepted",
                            sigers=[d.sign(ser=unrelated.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .event("delegated_inception_naming_the_inception", dip, "DelegationSourceAtInception",
                            sigers=[e0.sign(ser=dip.raw, index=0)], source=(0, dicp.said))
                     .event("delegated_inception_naming_the_wrong_event", dip, "Escrowed:PartiallyDelegated",
                            sigers=[e0.sign(ser=dip.raw, index=0)], source=(1, unrelated.said))
                     .record())

    # A delegator that does not delegate.
    d, dicp = delegator(140, cnfg=["DND"])
    e0, e1 = signer(150), signer(151)
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)])
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(dip)])
    scenarios.append(Scenario("delegator_forbids_delegation",
                              "The delegator's inception configures do-not-delegate (`DND`); a delegated"
                              " inception it anchors anyway is refused.", [dicp.pre, dip.pre])
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .event("delegated_inception", dip, "DelegationForbidden",
                            sigers=[e0.sign(ser=dip.raw, index=0)], source=(1, anchor.said))
                     .record())

    # Witnessing comes before delegation.
    d, dicp = delegator(160)
    e0, e1 = signer(170), signer(171)
    wits = [wit.verfer.qb64 for wit in ws]
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)], wits=wits, toad=1)
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(dip)])
    scenarios.append(Scenario("witnessed_delegate",
                              "A witnessed delegated inception, already anchored and naming its anchoring event,"
                              " arrives with no witness signature and waits for its witnesses, keeping its"
                              " source; a witness's receipt completes it.", [dicp.pre, dip.pre])
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .event("delegated_inception_without_witnesses", dip, "Escrowed:PartiallyWitnessed",
                            sigers=[e0.sign(ser=dip.raw, index=0)], source=(1, anchor.said))
                     .receipt("witness_receipt", eventing.receipt(pre=dip.pre, sn=0, said=dip.said),
                              "Escrowed:UnverifiedReceipt", wigers=[ws[1].sign(ser=dip.raw, index=1)])
                     .record())

    # A delegated rotation of an undelegated identifier.
    f0, f1, f2 = signer(180), signer(181), signer(182)
    icp = eventing.incept(keys=[f0.verfer.qb64], ndigs=[digest(f1)], code=MtrDex.Blake3_256)
    drt = eventing.deltate(pre=icp.pre, keys=[f1.verfer.qb64], dig=icp.said, sn=1, ndigs=[digest(f2)])
    scenarios.append(Scenario("delegated_rotation_of_an_undelegated_identifier",
                              "An undelegated identifier rotates with a `drt`. It has no delegator to approve"
                              " the rotation, and keripy accepts it as an ordinary rotation.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[f0.sign(ser=icp.raw, index=0)])
                     .event("delegated_rotation", drt, "Accepted", sigers=[f1.sign(ser=drt.raw, index=0)])
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

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "delegation-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("delegation-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
