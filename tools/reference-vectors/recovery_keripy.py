"""Generates and checks recovery rotation vectors from the pinned keripy.

``src/kever.rs`` and ``src/kevery.rs`` port keripy's recovery rotation: a rotation that supersedes
interactions accepted since the latest establishment event, signed with the keys that event
committed to. Each scenario offers keripy's ``Kevery``, unmodified, a log and a rotation recovering
it, the way keripy's parser would, processes escrows after each, and records what keripy then
holds, superseded events included, with ``kevery_keripy.Scenario``. keripy's clock is pinned.
keripy is pinned in ``pyproject.toml`` and ``uv.lock`` beside this file; run from the repository
root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/recovery_keripy.py --write   # or --check

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


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    ws = [signer(30 + index, transferable=False) for index in range(3)]
    wits = [wit.verfer.qb64 for wit in ws]
    scenarios = []

    # Recovering from compromised signing keys.
    a0, a1, a2 = signer(1), signer(2), signer(3)
    icp = eventing.incept(keys=[a0.verfer.qb64], ndigs=[digest(a1)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    ixn3 = eventing.interact(pre=icp.pre, dig=ixn2.said, sn=3)
    rot = eventing.rotate(pre=icp.pre, keys=[a1.verfer.qb64], dig=ixn1.said, sn=2, ndigs=[digest(a2)])
    after = eventing.interact(pre=icp.pre, dig=rot.said, sn=3)
    scenarios.append(Scenario("recovery_supersedes_interactions",
                              "Three interactions follow the inception. A rotation at the second interaction's"
                              " number, following the first and signed with the committed next key,"
                              " supersedes the second and third; the log continues from it, and the superseded"
                              " interactions offered again are likely duplicitous.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[a0.sign(ser=icp.raw, index=0)])
                     .event("first_interaction", ixn1, "Accepted", sigers=[a0.sign(ser=ixn1.raw, index=0)])
                     .event("second_interaction", ixn2, "Accepted", sigers=[a0.sign(ser=ixn2.raw, index=0)])
                     .event("third_interaction", ixn3, "Accepted", sigers=[a0.sign(ser=ixn3.raw, index=0)])
                     .event("recovery_rotation", rot, "Accepted", sigers=[a1.sign(ser=rot.raw, index=0)])
                     .event("interaction_after_recovery", after, "Accepted",
                            sigers=[a1.sign(ser=after.raw, index=0)])
                     .event("superseded_interaction_again", ixn3, "Escrowed:LikelyDuplicitous",
                            sigers=[a0.sign(ser=ixn3.raw, index=0)])
                     .record())

    # Recovering the first interaction.
    b0, b1, b2 = signer(10), signer(11), signer(12)
    icp = eventing.incept(keys=[b0.verfer.qb64], ndigs=[digest(b1)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    rot = eventing.rotate(pre=icp.pre, keys=[b1.verfer.qb64], dig=icp.said, sn=1, ndigs=[digest(b2)])
    scenarios.append(Scenario("recovery_of_the_first_interaction",
                              "A rotation at number one, following the inception, supersedes the interaction"
                              " accepted there.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[b0.sign(ser=icp.raw, index=0)])
                     .event("interaction", ixn1, "Accepted", sigers=[b0.sign(ser=ixn1.raw, index=0)])
                     .event("recovery_rotation", rot, "Accepted", sigers=[b1.sign(ser=rot.raw, index=0)])
                     .record())

    # A recovery naming the wrong prior event.
    c0, c1, c2 = signer(20), signer(21), signer(22)
    icp = eventing.incept(keys=[c0.verfer.qb64], ndigs=[digest(c1)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    rot = eventing.rotate(pre=icp.pre, keys=[c1.verfer.qb64], dig=ixn2.said, sn=2, ndigs=[digest(c2)])
    scenarios.append(Scenario("recovery_with_the_wrong_prior",
                              "A rotation at number two names the interaction it would supersede as its prior,"
                              " instead of the event before it, and is refused.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[c0.sign(ser=icp.raw, index=0)])
                     .event("first_interaction", ixn1, "Accepted", sigers=[c0.sign(ser=ixn1.raw, index=0)])
                     .event("second_interaction", ixn2, "Accepted", sigers=[c0.sign(ser=ixn2.raw, index=0)])
                     .event("recovery_rotation", rot, "PriorMismatch", sigers=[c1.sign(ser=rot.raw, index=0)])
                     .record())

    # A recovery gathering its signatures.
    m = [signer(40), signer(41)]
    n = [signer(42), signer(43)]
    icp = eventing.incept(keys=[key.verfer.qb64 for key in m], isith="2", ndigs=[digest(key) for key in n],
                          nsith="2", code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    rot = eventing.rotate(pre=icp.pre, keys=[key.verfer.qb64 for key in n], isith="2", dig=icp.said, sn=1,
                          ndigs=[digest(signer(44))])
    scenarios.append(Scenario("recovery_gathers_signatures",
                              "A two-of-two recovery rotation arrives with one signature and waits in the"
                              " partially signed escrow; its second signature completes it.", [icp.pre])
                     .event("inception", icp, "Accepted",
                            sigers=[key.sign(ser=icp.raw, index=index) for index, key in enumerate(m)])
                     .event("interaction", ixn1, "Accepted",
                            sigers=[key.sign(ser=ixn1.raw, index=index) for index, key in enumerate(m)])
                     .event("recovery_rotation_with_one_signature", rot, "Escrowed:PartiallySigned",
                            sigers=[n[0].sign(ser=rot.raw, index=0)])
                     .event("recovery_rotation_with_the_other_signature", rot, "Escrowed:PartiallySigned",
                            sigers=[n[1].sign(ser=rot.raw, index=1)])
                     .record())

    # A witnessed recovery.
    d0, d1, d2 = signer(50), signer(51), signer(52)
    icp = eventing.incept(keys=[d0.verfer.qb64], ndigs=[digest(d1)], wits=wits[:2], toad=1, code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    rot = eventing.rotate(pre=icp.pre, keys=[d1.verfer.qb64], dig=icp.said, sn=1, ndigs=[digest(d2)],
                          wits=wits[:2], cuts=[wits[0]], adds=[wits[2]], toad=1)
    scenarios.append(Scenario("recovery_keeps_the_witnesses",
                              "A witnessed recovery rotation cuts one witness and adds another. keripy derives"
                              " no witness changes for a rotation at or below the latest number, so the"
                              " witnesses stay as they were and the rotation is witnessed by a current one.",
                              [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[d0.sign(ser=icp.raw, index=0)],
                            wigers=[ws[0].sign(ser=icp.raw, index=0)])
                     .event("interaction", ixn1, "Accepted", sigers=[d0.sign(ser=ixn1.raw, index=0)],
                            wigers=[ws[0].sign(ser=ixn1.raw, index=0)])
                     .event("recovery_rotation", rot, "Accepted", sigers=[d1.sign(ser=rot.raw, index=0)],
                            wigers=[ws[1].sign(ser=rot.raw, index=1)])
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

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "recovery-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("recovery-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
