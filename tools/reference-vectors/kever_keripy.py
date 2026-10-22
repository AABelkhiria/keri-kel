"""Generates and checks key event log vectors from the pinned keripy.

``src/kever.rs`` ports keripy's ``Kever``. Every scenario here offers keripy's ``Kever`` a sequence
of signed events, unmodified, over a temporary keripy database, and records what it did with each:
the key state it accepted or the exception it raised. The first-seen time keripy would otherwise
read from the clock is passed in, as keripy's cloned-replay mode allows, and the clock itself is
pinned for the interactions keripy logs without it, so the states are deterministic. keripy is pinned in ``pyproject.toml`` and ``uv.lock`` beside this file; run from
the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/kever_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import sys
from dataclasses import asdict

from hio.help import decking
from keri.core import eventing, serdering
from keri.help import helping
from keri.core.coring import Dater, Diger, MtrDex
from keri.core.signing import Signer
from keri.db import basing

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"
STAMP = "2021-01-01T00:00:00.000000+00:00"


def signer(seed, transferable=True):
    return Signer(raw=bytes([seed]) * 32, code=MtrDex.Ed25519_Seed, transferable=transferable)


def digest(key):
    return Diger(ser=key.verfer.qb64b).qb64


def made(sad):
    """Builds an event keripy's own builders would refuse, so its validator can be asked about it."""
    return serdering.SerderKERI(sad=sad, makify=True)


class Scenario:
    """Offers keripy's `Kever` one signed event at a time and records each outcome."""

    def __init__(self, db, name, note):
        self.db = db
        self.name = name
        self.note = note
        self.kever = None
        self.steps = []

    def offer(self, label, serder, *, signers=(), witnesses=(), sigers=None, expect=None):
        """`expect` is the Rust error category for a step keripy refuses, or None for one it accepts."""
        sigers = sigers if sigers is not None else [key.sign(ser=serder.raw, index=index)
                                                    for index, key in signers]
        wigers = [key.sign(ser=serder.raw, index=index) for index, key in witnesses]
        raw = bytes(eventing.messagize(serder, sigers=sigers, wigers=wigers or None))
        step = {"label": label, "raw": raw.decode(), "raw_hex": raw.hex(), "rust_error_category": expect}
        dater = Dater(dts=STAMP)
        try:
            if self.kever is None:
                self.kever = eventing.Kever(serder=serder, sigers=sigers, wigers=wigers, db=self.db,
                                            dater=dater, cues=decking.Deck(), local=True)
            else:
                self.kever.update(serder=serder, sigers=sigers, wigers=wigers, dater=dater, local=True)
            step["keripy"] = {"accepted": True,
                              "state_json": json.dumps(asdict(self.kever.state()), separators=(",", ":"))}
            if expect is not None:
                raise AssertionError(f"{self.name}/{label}: keripy accepted a step expected to fail")
        except AssertionError:
            raise
        except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
            step["keripy"] = {"accepted": False, "error_category": type(error).__name__,
                              "error_message": str(error)[:300]}
            if expect is None:
                raise AssertionError(f"{self.name}/{label}: keripy refused a step expected to pass: {error}")
        self.steps.append(step)
        return self

    def record(self):
        return {"name": self.name, "note": self.note, "steps": self.steps}


def main():
    # keripy's `Kever.update` passes no replay datetime when it logs an interaction, so the first-seen
    # time of an interaction comes from the clock whatever `dater` is given. The clock is pinned.
    helping.nowIso8601 = lambda: STAMP
    db = basing.Baser(name="kever", temp=True, reopen=True)
    scenarios = []

    # A single-key identifier through every event kind, then every way an event can fail to follow.
    k0, k1, k2, k3, stranger = signer(1), signer(2), signer(3), signer(4), signer(5)
    icp = eventing.incept(keys=[k0.verfer.qb64], ndigs=[digest(k1)], code=MtrDex.Blake3_256)
    pre = icp.pre
    ixn1 = eventing.interact(pre=pre, dig=icp.said, sn=1)
    rot2 = eventing.rotate(pre=pre, keys=[k1.verfer.qb64], dig=ixn1.said, sn=2, ndigs=[digest(k2)])
    ixn3 = eventing.interact(pre=pre, dig=rot2.said, sn=3)
    rot4 = eventing.rotate(pre=pre, keys=[k2.verfer.qb64], dig=ixn3.said, sn=4, ndigs=[digest(k3)])
    other = eventing.incept(keys=[stranger.verfer.qb64], ndigs=[digest(k3)], code=MtrDex.Blake3_256)
    scenario = Scenario(db, "single_key_lifecycle",
                        "Inception, interaction, rotation, interaction, rotation; then one refused event per"
                        " rule, each leaving the state at the second rotation.")
    (scenario
     .offer("inception", icp, signers=[(0, k0)])
     .offer("interaction", ixn1, signers=[(0, k0)])
     .offer("rotation", rot2, signers=[(0, k1)])
     .offer("second_interaction", ixn3, signers=[(0, k1)])
     .offer("second_rotation", rot4, signers=[(0, k2)])
     .offer("interaction_with_wrong_prior", eventing.interact(pre=pre, dig=ixn3.said, sn=5), signers=[(0, k2)],
            expect="PriorMismatch")
     .offer("interaction_skipping_a_number", eventing.interact(pre=pre, dig=rot4.said, sn=6), signers=[(0, k2)],
            expect="OutOfOrder")
     .offer("rotation_skipping_a_number",
            eventing.rotate(pre=pre, keys=[k3.verfer.qb64], dig=rot4.said, sn=6, ndigs=[digest(k0)]),
            signers=[(0, k3)], expect="OutOfOrder")
     .offer("stale_rotation", eventing.rotate(pre=pre, keys=[k3.verfer.qb64], dig=ixn3.said, sn=4, ndigs=[digest(k0)]),
            signers=[(0, k3)], expect="Stale")
     .offer("interaction_signed_by_a_stranger", eventing.interact(pre=pre, dig=rot4.said, sn=5),
            signers=[(0, stranger)], expect="NoVerifiedSignatures")
     .offer("rotation_to_uncommitted_keys",
            eventing.rotate(pre=pre, keys=[stranger.verfer.qb64], dig=rot4.said, sn=5, ndigs=[digest(k0)]),
            signers=[(0, stranger)], expect="PriorNextNotSatisfied")
     .offer("event_of_another_identifier", eventing.interact(pre=other.pre, dig=other.said, sn=5),
            signers=[(0, stranger)], expect="IdentifierMismatch"))
    scenarios.append(scenario.record())

    # Three keys, two required.
    m = [signer(10), signer(11), signer(12)]
    n = [signer(13), signer(14), signer(15)]
    icp = eventing.incept(keys=[key.verfer.qb64 for key in m], isith="2", ndigs=[digest(key) for key in n],
                          nsith="2", code=MtrDex.Blake3_256)
    scenarios.append(Scenario(db, "two_of_three_partially_signed",
                              "One signature of the two required is refused as partially signed.")
                     .offer("inception_with_one_signature", icp, signers=[(0, m[0])], expect="NotFullySigned")
                     .record())
    scenarios.append(Scenario(db, "two_of_three", "Two signatures of three keys meet a threshold of two.")
                     .offer("inception_with_two_signatures", icp, signers=[(0, m[0]), (2, m[2])])
                     .record())

    # Weighted thresholds and a partial rotation that exposes only some of the committed keys.
    a, b, c = signer(20), signer(21), signer(22)
    x, y, z, w1, w2 = signer(23), signer(24), signer(25), signer(26), signer(27)
    halves = ["1/2", "1/2", "1/2"]
    icp = eventing.incept(keys=[a.verfer.qb64, b.verfer.qb64, c.verfer.qb64], isith=halves,
                          ndigs=[digest(x), digest(y), digest(z)], nsith=halves, code=MtrDex.Blake3_256)
    pre = icp.pre
    partial = eventing.rotate(pre=pre, keys=[x.verfer.qb64, y.verfer.qb64, w1.verfer.qb64], isith=halves,
                              dig=icp.said, sn=1, ndigs=[digest(a), digest(b)], nsith=["1/2", "1/2"])
    underexposed = eventing.rotate(pre=pre, keys=[x.verfer.qb64, w1.verfer.qb64, w2.verfer.qb64], isith=halves,
                                   dig=icp.said, sn=1, ndigs=[digest(a)], nsith="1")
    scenarios.append(Scenario(db, "weighted_partial_rotation",
                              "Weighted thresholds. A rotation exposing two of three committed keys, and a"
                              " new one signing only in the current list, meets both thresholds; one exposing"
                              " a single committed key meets the new threshold but not the prior next one.")
                     .offer("inception", icp, signers=[(0, a), (1, b)])
                     .offer("rotation_exposing_one_committed_key", underexposed,
                            sigers=[x.sign(ser=underexposed.raw, index=0, ondex=0),
                                    w1.sign(ser=underexposed.raw, index=1, only=True),
                                    w2.sign(ser=underexposed.raw, index=2, only=True)],
                            expect="PriorNextNotSatisfied")
                     .offer("rotation_exposing_two_committed_keys", partial,
                            sigers=[x.sign(ser=partial.raw, index=0, ondex=0),
                                    y.sign(ser=partial.raw, index=1, ondex=1),
                                    w1.sign(ser=partial.raw, index=2, only=True)])
                     .record())

    # Witnessed: three witnesses, two required; then a rotation that swaps one.
    ws = [signer(30 + index, transferable=False) for index in range(4)]
    wits = [wit.verfer.qb64 for wit in ws]
    d0, d1, d2 = signer(40), signer(41), signer(42)
    icp = eventing.incept(keys=[d0.verfer.qb64], ndigs=[digest(d1)], wits=wits[:3], toad=2, code=MtrDex.Blake3_256)
    pre = icp.pre
    rot = eventing.rotate(pre=pre, keys=[d1.verfer.qb64], dig=icp.said, sn=1, ndigs=[digest(d2)], wits=wits[:3],
                          cuts=[wits[0]], adds=[wits[3]], toad=2)
    ixn = eventing.interact(pre=pre, dig=rot.said, sn=2)
    cut_stranger = made({"v": icp.ked["v"], "t": "rot", "d": "", "i": pre, "s": "3", "p": ixn.said, "kt": "1",
                         "k": [d2.verfer.qb64], "nt": "1", "n": [digest(d0)], "bt": "1", "br": [wits[0]],
                         "ba": [], "a": []})
    add_current = made({"v": icp.ked["v"], "t": "rot", "d": "", "i": pre, "s": "3", "p": ixn.said, "kt": "1",
                        "k": [d2.verfer.qb64], "nt": "1", "n": [digest(d0)], "bt": "2", "br": [],
                        "ba": [wits[1]], "a": []})
    too_high = made({"v": icp.ked["v"], "t": "rot", "d": "", "i": pre, "s": "3", "p": ixn.said, "kt": "1",
                     "k": [d2.verfer.qb64], "nt": "1", "n": [digest(d0)], "bt": "4", "br": [], "ba": [], "a": []})
    scenarios.append(Scenario(db, "witnessed",
                              "Three witnesses with a threshold of two; a rotation cuts one and adds another,"
                              " and the following interaction is witnessed by the new set.")
                     .offer("inception_with_one_witness", icp, signers=[(0, d0)], witnesses=[(0, ws[0])],
                            expect="NotFullyWitnessed")
                     .offer("inception_with_two_witnesses", icp, signers=[(0, d0)],
                            witnesses=[(0, ws[0]), (2, ws[2])])
                     .offer("rotation_swapping_a_witness", rot, signers=[(0, d1)],
                            witnesses=[(1, ws[2]), (2, ws[3])])
                     .offer("interaction_witnessed_by_the_new_set", ixn, signers=[(0, d1)],
                            witnesses=[(0, ws[1]), (2, ws[3])])
                     .offer("rotation_cutting_a_former_witness", cut_stranger, signers=[(0, d2)],
                            witnesses=[(0, ws[1])], expect="CutNotAWitness")
                     .offer("rotation_adding_a_current_witness", add_current, signers=[(0, d2)],
                            witnesses=[(0, ws[1]), (1, ws[2])], expect="ConflictingWitnessLists")
                     .offer("rotation_with_witness_threshold_above_the_set", too_high, signers=[(0, d2)],
                            expect="InvalidWitnessThreshold")
                     .record())

    # Configuration traits and the two ways an identifier stops taking events.
    e0, e1, e2 = signer(50), signer(51), signer(52)
    icp = eventing.incept(keys=[e0.verfer.qb64], ndigs=[digest(e1)], cnfg=["EO", "DND"], code=MtrDex.Blake3_256)
    rot = eventing.rotate(pre=icp.pre, keys=[e1.verfer.qb64], dig=icp.said, sn=1, ndigs=[digest(e2)])
    scenarios.append(Scenario(db, "establishment_only",
                              "An identifier configured `EO` and `DND` refuses interactions and still rotates.")
                     .offer("inception", icp, signers=[(0, e0)])
                     .offer("interaction", eventing.interact(pre=icp.pre, dig=icp.said, sn=1), signers=[(0, e0)],
                            expect="EstablishmentOnly")
                     .offer("rotation", rot, signers=[(0, e1)])
                     .record())

    f0, f1 = signer(60), signer(61)
    icp = eventing.incept(keys=[f0.verfer.qb64], ndigs=[digest(f1)], code=MtrDex.Blake3_256)
    rot = eventing.rotate(pre=icp.pre, keys=[f1.verfer.qb64], dig=icp.said, sn=1, ndigs=[])
    scenarios.append(Scenario(db, "abandoned",
                              "A rotation committing to no next keys abandons the identifier.")
                     .offer("inception", icp, signers=[(0, f0)])
                     .offer("abandoning_rotation", rot, signers=[(0, f1)])
                     .offer("interaction_after_abandonment", eventing.interact(pre=icp.pre, dig=rot.said, sn=2),
                            signers=[(0, f1)], expect="NotTransferable")
                     .record())

    g0 = signer(70, transferable=False)
    icp = eventing.incept(keys=[g0.verfer.qb64], code=MtrDex.Ed25519N)
    scenarios.append(Scenario(db, "non_transferable",
                              "A basic non-transferable identifier is its key and takes no further events.")
                     .offer("inception", icp, signers=[(0, g0)])
                     .offer("interaction", eventing.interact(pre=icp.pre, dig=icp.said, sn=1), signers=[(0, g0)],
                            expect="NotTransferable")
                     .record())

    # Inceptions keripy's builder refuses to make, built by hand to ask its validator.
    h0, h1 = signer(80), signer(81)
    base = {"v": "KERI10JSON000000_", "t": "icp", "d": "", "i": "", "s": "0", "kt": "1", "k": [h0.verfer.qb64],
            "nt": "1", "n": [digest(h1)], "bt": "0", "b": [], "c": [], "a": []}
    for name, changes, category in [
        ("inception_threshold_above_keys", {"kt": "2"}, "ThresholdExceedsKeys"),
        ("inception_duplicate_witness", {"b": [wits[0], wits[0]], "bt": "1"}, "DuplicateWitness"),
        ("inception_witness_threshold_above_the_set", {"b": [wits[0]], "bt": "2"}, "InvalidWitnessThreshold"),
        ("inception_witness_threshold_without_witnesses", {"bt": "1"}, "InvalidWitnessThreshold"),
        ("inception_with_nonzero_sequence_number", {"s": "1"}, "NonZeroInception"),
    ]:
        serder = made({**base, **changes})
        scenarios.append(Scenario(db, name, "An inception keripy's validator refuses.")
                         .offer("inception", serder, signers=[(0, h0)], expect=category).record())

    # A recovery rotation, which keripy accepts and this port refuses until recovery is ported.
    r0, r1, r2 = signer(90), signer(91), signer(92)
    icp = eventing.incept(keys=[r0.verfer.qb64], ndigs=[digest(r1)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    recovery = eventing.rotate(pre=icp.pre, keys=[r1.verfer.qb64], dig=ixn1.said, sn=2, ndigs=[digest(r2)])
    recovery_scenario = Scenario(db, "recovery_rotation",
                                 "keripy accepts a rotation that replaces an interaction already accepted at its"
                                 " sequence number; the port refuses it as `RecoveryUnsupported`.")
    recovery_scenario.offer("inception", icp, signers=[(0, r0)]).offer("interaction", ixn1, signers=[(0, r0)]) \
        .offer("second_interaction", ixn2, signers=[(0, r0)]).offer("recovery_rotation", recovery, signers=[(0, r1)])

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/core/serdering.py"],
        "first_seen": STAMP,
        "scenarios": scenarios,
        "divergence_recovery_rotation": {**recovery_scenario.record(), "rust_error_category": "RecoveryUnsupported"},
    }
    db.close(clear=True)

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "kever-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("kever-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
