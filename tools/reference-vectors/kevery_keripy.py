"""Generates and checks log-processing vectors from the pinned keripy.

``src/kevery.rs`` ports keripy's ``Kevery``. Each scenario offers keripy's ``Kevery``, unmodified, a
sequence of messages over a temporary keripy database, the way keripy's parser would: a key event to
``processEvent``, then its attached receipt couples to ``processAttachedReceiptCouples``; a receipt
to ``processReceipt``. After every message ``processEscrows`` runs, and the generator records what
keripy then holds: each identifier's key state, the signatures stored for each accepted event, and
how many events and receipts are still waiting. keripy's clock is pinned, both for first-seen times
and for escrow ages. keripy is pinned in ``pyproject.toml`` and ``uv.lock`` beside this file; run
from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/kevery_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import datetime
import json
import pathlib
import sys
from dataclasses import asdict

from keri import kering
from keri.core import eventing
from keri.core.coring import Diger, MtrDex, Saider, Seqner
from keri.core.counting import Codens, Counter
from keri.core.signing import Signer
from keri.db import basing
from keri.db.dbing import dgKey, snKey
from keri.help import helping

from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-22"
STAMP = "2021-01-01T00:00:00.000000+00:00"

OUTCOMES = {
    kering.MissingSignatureError: "PartiallySigned",
    kering.MissingWitnessSignatureError: "PartiallyWitnessed",
    kering.UnverifiedReceiptError: "UnverifiedReceipt",
    kering.MissingDelegationError: "PartiallyDelegated",
}


def signer(seed, transferable=True):
    return Signer(raw=bytes([seed]) * 32, code=MtrDex.Ed25519_Seed, transferable=transferable)


def digest(key):
    return Diger(ser=key.verfer.qb64b).qb64


class Scenario:
    """Offers keripy's `Kevery` one message at a time and snapshots what it holds after each."""

    def __init__(self, name, note, identifiers):
        self.name = name
        self.note = note
        self.identifiers = identifiers
        self.db = basing.Baser(name=name, temp=True, reopen=True)
        self.kevery = eventing.Kevery(db=self.db)
        self.steps = []

    def event(self, label, serder, expect, *, sigers=(), wigers=(), cigars=(), source=None):
        raw = bytes(eventing.messagize(serder, sigers=list(sigers) or None, wigers=list(wigers) or None,
                                       cigars=list(cigars) or None))
        seqner = saider = None
        if source is not None:
            # A delegated event names its delegating event in a seal source couple, which keripy's
            # parser hands to `processEvent` apart from the signatures.
            seqner, saider = Seqner(sn=source[0]), Saider(qb64=source[1])
            raw += Counter(Codens.SealSourceCouples, count=1, gvrsn=kering.Vrsn_1_0).qb64b
            raw += seqner.qb64b + saider.qb64b

        def run():
            self.kevery.processEvent(serder=serder, sigers=list(sigers), wigers=list(wigers),
                                     delseqner=seqner, delsaider=saider)
            if cigars:
                self.kevery.processAttachedReceiptCouples(serder, list(cigars))
        return self._offer(label, raw, expect, run)

    def receipt(self, label, receipt, expect, *, wigers=(), cigars=()):
        raw = bytes(eventing.messagize(receipt, wigers=list(wigers) or None, cigars=list(cigars) or None))
        return self._offer(label, raw, expect,
                           lambda: self.kevery.processReceipt(serder=receipt, cigars=list(cigars), wigers=list(wigers)))

    def _offer(self, label, raw, expect, run):
        step = {"label": label, "raw": raw.decode(), "raw_hex": raw.hex(), "rust_outcome": expect}
        try:
            run()
            step["keripy"] = {"raised": None}
        except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
            step["keripy"] = {"raised": type(error).__name__, "message": str(error)[:240]}
            mapped = OUTCOMES.get(type(error))
            if mapped is not None and expect != f"Escrowed:{mapped}":
                raise AssertionError(f"{self.name}/{label}: keripy escrowed {mapped}, expected {expect}")
        self.kevery.processEscrows()
        step["after"] = self.snapshot()
        self.steps.append(step)
        return self

    def snapshot(self):
        states = []
        for pre in self.identifiers:
            kever = self.kevery.kevers.get(pre)
            if kever is None:
                states.append({"identifier": pre, "state_json": None, "events": []})
                continue
            events = []
            for sn in range(kever.sn + 1):
                dig = self.db.getKeLast(snKey(pre, sn))
                if dig is None:
                    continue
                key = dgKey(pre, bytes(dig))
                event = {
                    "sequence_number": sn,
                    "said": bytes(dig).decode(),
                    "signatures": sorted(bytes(sig).decode() for sig in self.db.getSigs(key)),
                    "witness_signatures": sorted(bytes(wig).decode() for wig in self.db.getWigs(key)),
                    "receipts": sorted(bytes(rct).decode() for rct in self.db.getRcts(key)),
                }
                source = self.db.getAes(key)
                if source is not None:
                    # The delegating event's sequence number and SAID, stored with a delegated event.
                    seqner = Seqner(qb64b=bytes(source))
                    event["delegation"] = {"sequence_number": seqner.sn,
                                           "said": bytes(source)[len(seqner.qb64b):].decode()}
                events.append(event)
            states.append({"identifier": pre,
                           "state_json": json.dumps(asdict(kever.state()), separators=(",", ":")),
                           "events": events})
        escrowed = {(bytes(key), bytes(dig)) for key, dig in self.db.getPseItemIter(key=b"")}
        escrowed |= {(bytes(key), bytes(dig)) for key, dig in self.db.getPweItemIter(key=b"")}
        escrowed |= {(bytes(snKey(pre, sn)), dig.encode()) for (pre,), sn, dig in self.db.pdes.getOnItemIter(keys=b"")}
        waiting = sum(1 for _ in self.db.uwes.getItemIter()) + sum(1 for _ in self.db.getUreItemIter(key=b""))
        return {"states": states, "escrowed_events": len(escrowed), "waiting_receipts": waiting}

    def record(self):
        self.db.close(clear=True)
        return {"name": self.name, "note": self.note, "steps": self.steps}


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    ws = [signer(30 + index, transferable=False) for index in range(5)]
    wits = [wit.verfer.qb64 for wit in ws]
    stranger = signer(39, transferable=False)
    scenarios = []

    # Receipts complete an inception waiting for its witnesses.
    a0, a1 = signer(1), signer(2)
    icp = eventing.incept(keys=[a0.verfer.qb64], ndigs=[digest(a1)], wits=wits[:3], toad=2, code=MtrDex.Blake3_256)
    rct = eventing.receipt(pre=icp.pre, sn=0, said=icp.said)
    scenarios.append(Scenario("receipts_complete_a_witnessed_inception",
                              "An inception needing two of three witnesses arrives with none. A witness's indexed"
                              " signature, then another witness's receipt couple, arrive as receipts before it is"
                              " accepted; each is matched to the waiting event, and the second completes it.",
                              [icp.pre])
                     .event("inception_without_witnesses", icp, "Escrowed:PartiallyWitnessed",
                            sigers=[a0.sign(ser=icp.raw, index=0)])
                     .receipt("first_witness_signature", rct, "Escrowed:UnverifiedReceipt",
                              wigers=[ws[0].sign(ser=icp.raw, index=0)])
                     .receipt("second_witness_couple", rct, "Escrowed:UnverifiedReceipt",
                              cigars=[ws[1].sign(ser=icp.raw)])
                     .record())

    # Signatures gathered across two offers of the same event.
    m = [signer(10), signer(11), signer(12)]
    icp = eventing.incept(keys=[key.verfer.qb64 for key in m], isith="2", ndigs=[digest(signer(13))],
                          code=MtrDex.Blake3_256)
    scenarios.append(Scenario("signatures_gathered_across_offers",
                              "A two-of-three inception is offered with one signature, then again with another;"
                              " the escrow holds both and accepts the event.", [icp.pre])
                     .event("inception_with_first_signature", icp, "Escrowed:PartiallySigned",
                            sigers=[m[0].sign(ser=icp.raw, index=0)])
                     .event("inception_with_third_signature", icp, "Escrowed:PartiallySigned",
                            sigers=[m[2].sign(ser=icp.raw, index=2)])
                     .record())

    # Receipts and duplicates for events already accepted.
    b0, b1, b2 = signer(20), signer(21), signer(22)
    icp = eventing.incept(keys=[b0.verfer.qb64, b1.verfer.qb64], isith="1", ndigs=[digest(b2)], wits=wits[:2],
                          toad=1, code=MtrDex.Blake3_256)
    ixn = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    other = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=[{"i": icp.pre}])
    scenarios.append(Scenario("receipts_and_duplicates_for_accepted_events",
                              "An inception accepted with one of two witnesses gains the other's signature by"
                              " receipt, a stranger's receipt couple, and the second controller signature when"
                              " offered again. A receipt for another event at the same number is stale, and a"
                              " different interaction at an accepted number is likely duplicitous.", [icp.pre])
                     .event("inception_with_one_witness", icp, "Accepted",
                            sigers=[b0.sign(ser=icp.raw, index=0)], wigers=[ws[0].sign(ser=icp.raw, index=0)])
                     .receipt("second_witness_signature", eventing.receipt(pre=icp.pre, sn=0, said=icp.said),
                              "Receipted", wigers=[ws[1].sign(ser=icp.raw, index=1)])
                     .receipt("stranger_couple", eventing.receipt(pre=icp.pre, sn=0, said=icp.said), "Receipted",
                              cigars=[stranger.sign(ser=icp.raw)])
                     .event("inception_again_with_second_signature", icp, "Duplicate",
                            sigers=[b1.sign(ser=icp.raw, index=1)])
                     .receipt("receipt_for_another_event", eventing.receipt(pre=icp.pre, sn=0, said=ixn.said),
                              "StaleReceipt", wigers=[ws[0].sign(ser=ixn.raw, index=0)])
                     .event("interaction", ixn, "Accepted", sigers=[b0.sign(ser=ixn.raw, index=0)],
                            wigers=[ws[1].sign(ser=ixn.raw, index=1)])
                     .event("another_interaction_at_the_same_number", other, "LikelyDuplicitous",
                            sigers=[b0.sign(ser=other.raw, index=0)], wigers=[ws[1].sign(ser=other.raw, index=1)])
                     .record())

    # A rotation waiting for witnesses of its new set.
    c0, c1, c2 = signer(40), signer(41), signer(42)
    icp = eventing.incept(keys=[c0.verfer.qb64], ndigs=[digest(c1)], wits=wits[:3], toad=2, code=MtrDex.Blake3_256)
    rot = eventing.rotate(pre=icp.pre, keys=[c1.verfer.qb64], dig=icp.said, sn=1, ndigs=[digest(c2)],
                          wits=wits[:3], cuts=[wits[0]], adds=[wits[3]], toad=2)
    scenarios.append(Scenario("receipt_completes_a_rotation_changing_witnesses",
                              "A rotation cutting one witness and adding another arrives signed by the added"
                              " witness only; a receipt from a remaining witness, indexed into the new set,"
                              " completes it.", [icp.pre])
                     .event("inception", icp, "Accepted", sigers=[c0.sign(ser=icp.raw, index=0)],
                            wigers=[ws[0].sign(ser=icp.raw, index=0), ws[1].sign(ser=icp.raw, index=1)])
                     .event("rotation_with_the_added_witness", rot, "Escrowed:PartiallyWitnessed",
                            sigers=[c1.sign(ser=rot.raw, index=0)], wigers=[ws[3].sign(ser=rot.raw, index=2)])
                     .receipt("receipt_from_a_remaining_witness", eventing.receipt(pre=icp.pre, sn=1, said=rot.said),
                              "Escrowed:UnverifiedReceipt", wigers=[ws[1].sign(ser=rot.raw, index=0)])
                     .record())

    # keripy's attached-couple defect, recorded as a divergence.
    d0, d1 = signer(50), signer(51)
    icp = eventing.incept(keys=[d0.verfer.qb64], ndigs=[digest(d1)], wits=wits[:2], toad=1, code=MtrDex.Blake3_256)
    divergence = Scenario("attached_witness_couple",
                          "An inception carries one witness's indexed signature and the other witness's receipt"
                          " couple. keripy stores the couple as a plain receipt, because"
                          " `processAttachedReceiptCouples` compares the couple's key against prefix objects;"
                          " the port stores it as that witness's signature.", [icp.pre])
    divergence.event("inception_with_signature_and_couple", icp, "Accepted",
                     sigers=[d0.sign(ser=icp.raw, index=0)], wigers=[ws[0].sign(ser=icp.raw, index=0)],
                     cigars=[ws[1].sign(ser=icp.raw)])

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py"],
        "now": STAMP,
        "scenarios": scenarios,
        "divergence_attached_witness_couple": {
            **divergence.record(),
            "promoted_witness": wits[1],
        },
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "kevery-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("kevery-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
