"""Generates and checks query vectors from the pinned keripy.

``src/query.rs`` ports keripy's answers to queries (``qry``): ``logs`` replays an identifier's log,
``ksn`` gives its key state, and ``mbx`` opens its mailbox, each only once the identifier's log holds
what the query asks for; otherwise the query waits in an escrow and is answered once it does.
``Kevery.processQuery`` decides, and ``processQueryNotFound`` retries. Each scenario offers keripy,
unmodified, events and queries in some order, signed as keripy's agents sign them, processes
escrows after each, and records what keripy then holds and the answers it cued, with
``kevery_keripy.Scenario``. keripy's clock is pinned. keripy is pinned in ``pyproject.toml`` and
``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/queries_keripy.py --write   # or --check

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

GENERATED_ON = "2026-10-24"


def query(route, **arguments):
    return eventing.query(route=route, query=arguments, stamp=STAMP)


class Controller:
    """A single-key controller with three keys in rotation order."""

    def __init__(self, seed):
        self.keys = [signer(seed + index) for index in range(3)]
        self.icp = eventing.incept(keys=[self.keys[0].verfer.qb64], ndigs=[digest(self.keys[1])],
                                   code=MtrDex.Blake3_256)
        self.pre = self.icp.pre

    def interaction(self, sn, prior, data=None):
        return eventing.interact(pre=self.pre, dig=prior.said, sn=sn, data=data)

    def signed(self, serder, key=0):
        return dict(sigers=[self.keys[key].sign(ser=serder.raw, index=0)])


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    watcher = signer(30, transferable=False)
    wid = watcher.verfer.qb64
    requester = Controller(50)
    asking = dict(key=requester.keys[0], requester=requester.pre)
    scenarios = []

    # Replays of a log.
    c = Controller(1)
    ixn1 = c.interaction(1, c.icp)
    anchored = {"i": c.pre, "s": "0", "d": c.icp.said}
    ixn2 = c.interaction(2, ixn1, data=[anchored])
    missing = {"i": c.pre, "s": "1", "d": ixn1.said}
    scenarios.append(Scenario("log_replays",
                              "A log of three events is replayed whole, from its second first-seen event, and from"
                              " an anchor one of its events holds; its key state and mailbox are answered too.",
                              [c.pre])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .event("first_interaction", ixn1, "Accepted", **c.signed(ixn1))
                     .event("second_interaction", ixn2, "Accepted", **c.signed(ixn2))
                     .query("whole_log", query("logs", i=c.pre, src=wid), "Answered", **asking)
                     .query("log_from_the_second", query("logs", i=c.pre, src=wid, fn="1"), "Answered", **asking)
                     .query("log_by_anchor", query("logs", i=c.pre, src=wid, a=anchored), "Answered", **asking)
                     .query("key_state", query("ksn", i=c.pre, src=wid), "Answered", **asking)
                     .query("mailbox", query("mbx", i=c.pre, src=wid, topics={"/receipt": 0}), "Answered",
                            **asking)
                     .query("log_by_an_anchor_no_event_holds", query("logs", i=c.pre, src=wid, a=missing),
                            "Escrowed:QueryNotFound", **asking)
                     .record())

    # Queries waiting for the log.
    c = Controller(10)
    ixn1 = c.interaction(1, c.icp)
    ixn2 = c.interaction(2, ixn1)
    scenarios.append(Scenario("queries_wait_for_the_log",
                              "Queries for an identifier not seen yet, and for a sequence number its log has not"
                              " reached, wait, and are answered once the events arrive.", [c.pre])
                     .query("key_state_of_an_unknown_identifier", query("ksn", i=c.pre, src=wid),
                            "Escrowed:QueryNotFound", **asking)
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .event("first_interaction", ixn1, "Accepted", **c.signed(ixn1))
                     .query("log_to_the_second_interaction", query("logs", i=c.pre, src=wid, s="2"),
                            "Escrowed:QueryNotFound", **asking)
                     .event("second_interaction", ixn2, "Accepted", **c.signed(ixn2))
                     .record())

    # A recovered log replays what was superseded.
    c = Controller(20)
    ixn1 = c.interaction(1, c.icp)
    ixn2 = c.interaction(2, ixn1)
    rot = eventing.rotate(pre=c.pre, keys=[c.keys[1].verfer.qb64], dig=c.icp.said, sn=1,
                          ndigs=[digest(c.keys[2])])
    scenarios.append(Scenario("recovered_log",
                              "After a recovery rotation supersedes two interactions, the log replays every event"
                              " in the order first seen, the superseded ones included.", [c.pre])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .event("first_interaction", ixn1, "Accepted", **c.signed(ixn1))
                     .event("second_interaction", ixn2, "Accepted", **c.signed(ixn2))
                     .event("recovery_rotation", rot, "Accepted", **c.signed(rot, key=1))
                     .query("whole_log", query("logs", i=c.pre, src=wid), "Answered", **asking)
                     .record())

    # A delegated log replays its delegator's.
    d, dicp = delegator(80)
    e0, e1 = signer(90), signer(91)
    dip = eventing.delcept(keys=[e0.verfer.qb64], delpre=dicp.pre, ndigs=[digest(e1)])
    anchor = eventing.interact(pre=dicp.pre, dig=dicp.said, sn=1, data=[seal(dip)])
    scenarios.append(Scenario("delegated_log",
                              "A delegated identifier's log is replayed followed by its delegator's whole log.",
                              [dicp.pre, dip.pre])
                     .event("delegator_inception", dicp, "Accepted", sigers=[d.sign(ser=dicp.raw, index=0)])
                     .event("delegator_anchors_the_inception", anchor, "Accepted",
                            sigers=[d.sign(ser=anchor.raw, index=0)])
                     .event("delegated_inception", dip, "Accepted", sigers=[e0.sign(ser=dip.raw, index=0)],
                            source=(1, anchor.said))
                     .query("delegated_log", query("logs", i=dip.pre, src=wid), "Answered", **asking)
                     .record())

    # A query signed only by a non-transferable key.
    c = Controller(40)
    known = query("ksn", i=c.pre, src=wid)
    unknown = query("ksn", i=requester.pre, src=wid)
    scenarios.append(Scenario("non_transferable_requester",
                              "A query signed by a non-transferable key is answered when the log holds what it"
                              " asks for; when it does not, keripy cannot escrow it without a transferable"
                              " requester and refuses it.", [c.pre])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .query("key_state", known, "Answered", cigar=watcher.sign(ser=known.raw))
                     .query("key_state_of_an_unknown_identifier", unknown, "QueryUnanswerable",
                            cigar=watcher.sign(ser=unknown.raw))
                     .record())

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/db/basing.py"],
        "now": STAMP,
        "scenarios": scenarios,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "queries-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("queries-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
