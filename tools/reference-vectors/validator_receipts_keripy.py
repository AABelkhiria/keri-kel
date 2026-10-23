"""Generates and checks validator receipt vectors from the pinned keripy.

``src/kevery.rs`` ports keripy's receipts from transferable identifiers, validators: a receipt
(``rct``) carrying a validator's indexed signature group (``-F``), and receipt quadruples (``-D``)
attached to an event. Each signature is verified against the keys of the validator's establishment
event the receipt names. Each scenario offers keripy's ``Kevery``, unmodified, messages in some
order, the way keripy's parser would, processes escrows after each, and records what keripy then
holds, with ``kevery_keripy.Scenario``. keripy's clock is pinned. keripy is pinned in
``pyproject.toml`` and ``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/validator_receipts_keripy.py --write   # or --check

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

GENERATED_ON = "2026-10-23"


def identifier(seed):
    """A single-key identifier: its signers and its inception."""
    keys = [signer(seed), signer(seed + 1), signer(seed + 2)]
    icp = eventing.incept(keys=[keys[0].verfer.qb64], ndigs=[digest(keys[1])], code=MtrDex.Blake3_256)
    return keys, icp


def sign(key, serder, index=0):
    return key.sign(ser=serder.raw, index=index)


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    scenarios = []

    # A validator receipts an accepted event.
    v, vicp = identifier(1)
    c, cicp = identifier(10)
    rct = eventing.receipt(pre=cicp.pre, sn=0, said=cicp.said)
    group = (vicp.pre, 0, vicp.said, [sign(v[0], cicp)])
    scenarios.append(Scenario("validator_receipts_an_accepted_event",
                              "A validator's receipt of an accepted inception, signed with the keys of the"
                              " validator's inception, is stored; the same receipt again changes nothing.",
                              [vicp.pre, cicp.pre])
                     .event("validator_inception", vicp, "Accepted", sigers=[sign(v[0], vicp)])
                     .event("controller_inception", cicp, "Accepted", sigers=[sign(c[0], cicp)])
                     .receipt("validator_receipt", rct, "Receipted", group=group)
                     .receipt("validator_receipt_again", rct, "Receipted", group=group)
                     .record())

    # Receipts arriving before what they need.
    v, vicp = identifier(20)
    c, cicp = identifier(30)
    rct = eventing.receipt(pre=cicp.pre, sn=0, said=cicp.said)
    scenarios.append(Scenario("receipt_before_both_events",
                              "A validator's receipt arrives before the receipted event and before the"
                              " validator's own inception. It waits for the receipted event, then for the"
                              " validator's, and is stored once both are accepted.", [vicp.pre, cicp.pre])
                     .receipt("validator_receipt", rct, "Escrowed:UnverifiedReceipt",
                              group=(vicp.pre, 0, vicp.said, [sign(v[0], cicp)]))
                     .event("controller_inception", cicp, "Accepted", sigers=[sign(c[0], cicp)])
                     .event("validator_inception", vicp, "Accepted", sigers=[sign(v[0], vicp)])
                     .record())

    v, vicp = identifier(40)
    c, cicp = identifier(50)
    rct = eventing.receipt(pre=cicp.pre, sn=0, said=cicp.said)
    scenarios.append(Scenario("receipt_before_the_validator",
                              "A validator's receipt of an accepted event arrives before the validator's"
                              " inception; it waits, and is stored once the inception is accepted.",
                              [vicp.pre, cicp.pre])
                     .event("controller_inception", cicp, "Accepted", sigers=[sign(c[0], cicp)])
                     .receipt("validator_receipt", rct, "Escrowed:UnverifiedTransferableReceipt",
                              group=(vicp.pre, 0, vicp.said, [sign(v[0], cicp)]))
                     .event("validator_inception", vicp, "Accepted", sigers=[sign(v[0], vicp)])
                     .record())

    # Receipts naming the wrong validator event, or failing to verify.
    v, vicp = identifier(60)
    vixn = eventing.interact(pre=vicp.pre, dig=vicp.said, sn=1)
    c, cicp = identifier(70)
    rct = eventing.receipt(pre=cicp.pre, sn=0, said=cicp.said)
    stranger = signer(79)
    scenarios.append(Scenario("receipts_keripy_refuses_or_skips",
                              "Validator receipts naming another event than the validator's at that number, or an"
                              " interaction, which has no keys, or a key position past the validator's keys, are"
                              " refused; one whose signature fails is skipped.", [vicp.pre, cicp.pre])
                     .event("validator_inception", vicp, "Accepted", sigers=[sign(v[0], vicp)])
                     .event("validator_interaction", vixn, "Accepted", sigers=[sign(v[0], vixn)])
                     .event("controller_inception", cicp, "Accepted", sigers=[sign(c[0], cicp)])
                     .receipt("receipt_naming_another_event", rct, "ReceiptorEventMismatch",
                              group=(vicp.pre, 0, vixn.said, [sign(v[0], cicp)]))
                     .receipt("receipt_naming_an_interaction", rct, "ReceiptorEventHasNoKeys",
                              group=(vicp.pre, 1, vixn.said, [sign(v[0], cicp)]))
                     .receipt("receipt_past_the_keys", rct, "ReceiptSignatureIndexOutOfRange",
                              group=(vicp.pre, 0, vicp.said, [sign(v[0], cicp, index=1)]))
                     .receipt("receipt_with_a_bad_signature", rct, "Receipted",
                              group=(vicp.pre, 0, vicp.said, [sign(stranger, cicp)]))
                     .record())

    # A receipt signed with keys a validator has since rotated away.
    v, vicp = identifier(80)
    vrot = eventing.rotate(pre=vicp.pre, keys=[v[1].verfer.qb64], dig=vicp.said, sn=1, ndigs=[digest(v[2])])
    c, cicp = identifier(90)
    rct = eventing.receipt(pre=cicp.pre, sn=0, said=cicp.said)
    scenarios.append(Scenario("receipts_from_a_rotated_validator",
                              "A validator that has rotated receipts the same event twice: once signed with the"
                              " keys of its inception, naming the inception, and once with its rotated keys,"
                              " naming the rotation. Both are stored.", [vicp.pre, cicp.pre])
                     .event("validator_inception", vicp, "Accepted", sigers=[sign(v[0], vicp)])
                     .event("validator_rotation", vrot, "Accepted", sigers=[sign(v[1], vrot)])
                     .event("controller_inception", cicp, "Accepted", sigers=[sign(c[0], cicp)])
                     .receipt("receipt_with_the_inception_keys", rct, "Receipted",
                              group=(vicp.pre, 0, vicp.said, [sign(v[0], cicp)]))
                     .receipt("receipt_with_the_rotated_keys", rct, "Receipted",
                              group=(vicp.pre, 1, vrot.said, [sign(v[1], cicp)]))
                     .record())

    # Receipt quadruples attached to events.
    v, vicp = identifier(100)
    w, wicp = identifier(110)
    c, cicp = identifier(120)
    cixn = eventing.interact(pre=cicp.pre, dig=cicp.said, sn=1)
    cixn2 = eventing.interact(pre=cicp.pre, dig=cixn.said, sn=2)
    scenarios.append(Scenario("quadruples_attached_to_events",
                              "Events carry validator receipt quadruples. One from a known validator is stored"
                              " with the event; one from a validator not seen yet waits and is stored once its"
                              " inception is accepted; one whose signature fails is dropped. Each event is"
                              " accepted whatever becomes of its quadruples.", [vicp.pre, wicp.pre, cicp.pre])
                     .event("validator_inception", vicp, "Accepted", sigers=[sign(v[0], vicp)])
                     .event("inception_with_a_quadruple", cicp, "Accepted", sigers=[sign(c[0], cicp)],
                            trqs=[(vicp.pre, 0, vicp.said, sign(v[0], cicp))])
                     .event("interaction_with_an_unknown_validator", cixn, "Accepted", sigers=[sign(c[0], cixn)],
                            trqs=[(wicp.pre, 0, wicp.said, sign(w[0], cixn))])
                     .event("second_validator_inception", wicp, "Accepted", sigers=[sign(w[0], wicp)])
                     .event("interaction_with_a_bad_quadruple", cixn2, "Accepted", sigers=[sign(c[0], cixn2)],
                            trqs=[(vicp.pre, 0, vicp.said, sign(w[0], cixn2))])
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

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "validator-receipts-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("validator-receipts-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
