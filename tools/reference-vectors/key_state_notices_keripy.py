"""Generates and checks key state notice vectors from the pinned keripy.

``src/kevery.rs`` ports keripy's handling of key state notices: a reply (``rpy``) on route
``/ksn/{source}`` in which an actor reports an identifier's key state. ``Revery.processReply``
verifies the reply and ``Kevery.processReplyKeyStateNotice`` decides whether to keep it. Each
scenario offers keripy, unmodified, events and notices in some order, the way keripy's parser
would, processes event and reply escrows after each, and records what keripy then holds, the
notices it kept included, with ``kevery_keripy.Scenario``. keripy's clock is pinned. keripy is
pinned in ``pyproject.toml`` and ``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/key_state_notices_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import datetime
import itertools
import json
import pathlib
import sys
from dataclasses import asdict

from keri.core import eventing
from keri.core.coring import MtrDex
from keri.db import basing
from keri.help import helping

from kevery_keripy import STAMP, Scenario, digest, signer
from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-23"
EARLIER = "2021-01-01T00:00:01.000000+00:00"
LATER = "2021-01-01T00:00:02.000000+00:00"
SOURCES = itertools.count()


def state_after(events):
    """The key state keripy holds after accepting `events`, each `(serder, sigers, wigers)`."""
    db = basing.Baser(name=f"source-{next(SOURCES)}", temp=True, reopen=True)
    kevery = eventing.Kevery(db=db)
    for serder, sigers, wigers in events:
        kevery.processEvent(serder=serder, sigers=sigers, wigers=wigers)
    state = kevery.kevers[events[0][0].pre].state()
    db.close(clear=True)
    return state


def notice(source, state, stamp=STAMP):
    """A key state notice from `source` reporting `state`."""
    return eventing.reply(route=f"/ksn/{source}", data=asdict(state), stamp=stamp)


class Controller:
    """A single-key controller witnessed by one witness, with an interaction and a fork of it."""

    def __init__(self, seed, witness):
        self.keys = [signer(seed), signer(seed + 1)]
        self.witness = witness
        wits = [witness.verfer.qb64]
        self.icp = eventing.incept(keys=[self.keys[0].verfer.qb64], ndigs=[digest(self.keys[1])], wits=wits,
                                   toad=1, code=MtrDex.Blake3_256)
        self.ixn = eventing.interact(pre=self.icp.pre, dig=self.icp.said, sn=1)
        self.fork = eventing.interact(pre=self.icp.pre, dig=self.icp.said, sn=1, data=[{"i": self.icp.pre}])
        self.pre = self.icp.pre

    def signed(self, serder):
        return dict(sigers=[self.keys[0].sign(ser=serder.raw, index=0)],
                    wigers=[self.witness.sign(ser=serder.raw, index=0)])

    def state(self, *serders):
        return state_after([(serder, *self.signed(serder).values()) for serder in serders])


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    w = signer(30, transferable=False)
    stranger = signer(39, transferable=False)
    watcher = signer(38, transferable=False)
    scenarios = []

    # A witness and the controller itself report the state.
    c = Controller(1, w)
    at_inception = notice(w.verfer.qb64, c.state(c.icp))
    own = notice(c.pre, c.state(c.icp))
    scenarios.append(Scenario("witness_and_controller_report",
                              "A witness of the identifier, signing as its non-transferable key, and the"
                              " controller, signing with the keys of its inception, each report the state at the"
                              " inception; both notices are kept, one per source.", [c.pre])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .reply("witness_notice", at_inception, "KeyStateAccepted", cigars=[w.sign(ser=at_inception.raw)])
                     .reply("controller_notice", own, "KeyStateAccepted",
                            group=(c.pre, 0, c.icp.said, [c.keys[0].sign(ser=own.raw, index=0)]))
                     .record())

    # Notices ahead of, behind, and contradicting the local log.
    c = Controller(10, w)
    ahead = notice(w.verfer.qb64, c.state(c.icp, c.ixn))
    # Later notices from the same source carry later dates, as a source's own replies do.
    behind = notice(w.verfer.qb64, c.state(c.icp), stamp=EARLIER)
    forked = notice(w.verfer.qb64, c.state(c.icp, c.fork), stamp=LATER)
    scenarios.append(Scenario("notices_against_the_local_log",
                              "A notice of a state ahead of the local log is kept, since nothing local contradicts"
                              " it. Once the log has caught up, a notice of an earlier state is stale, and one"
                              " whose latest event is not the local event at that number is refused.", [c.pre])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .reply("notice_ahead", ahead, "KeyStateAccepted", cigars=[w.sign(ser=ahead.raw)])
                     .event("interaction", c.ixn, "Accepted", **c.signed(c.ixn))
                     .reply("notice_behind", behind, "StaleKeyState", cigars=[w.sign(ser=behind.raw)])
                     .reply("notice_of_a_fork", forked, "KeyStateMismatch", cigars=[w.sign(ser=forked.raw)])
                     .record())

    # A transferable source not known yet.
    c = Controller(20, w)
    v = [signer(25), signer(26)]
    vicp = eventing.incept(keys=[v[0].verfer.qb64], ndigs=[digest(v[1])], code=MtrDex.Blake3_256)
    report = notice(vicp.pre, c.state(c.icp))
    scenarios.append(Scenario("notice_from_an_unknown_signer",
                              "A transferable source reports a state before its own inception is known; the"
                              " notice waits in the reply escrow and is kept once the inception is accepted.",
                              [c.pre, vicp.pre])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .reply("notice", report, "Escrowed:UnverifiedReply",
                            group=(vicp.pre, 0, vicp.said, [v[0].sign(ser=report.raw, index=0)]))
                     .event("source_inception", vicp, "Accepted", sigers=[v[0].sign(ser=vicp.raw, index=0)])
                     .record())

    # Signatures that do not establish a notice.
    c = Controller(40, w)
    state = c.state(c.icp)
    forged = notice(w.verfer.qb64, state)
    foreign = notice(w.verfer.qb64, state)
    scenarios.append(Scenario("notices_not_signed_by_their_source",
                              "A notice whose signature does not verify, and one signed by someone other than the"
                              " source its route names, are not kept.", [c.pre])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .reply("notice_with_a_bad_signature", forged, "UnverifiedReply",
                            cigars=[w.sign(ser=at_inception.raw)])
                     .reply("notice_signed_by_another", foreign, "UnverifiedReply",
                            cigars=[stranger.sign(ser=foreign.raw)])
                     .record())

    # keripy's trust policy, as its controllers apply it.
    c = Controller(50, w)
    state = c.state(c.icp)
    untrusted = notice(stranger.verfer.qb64, state)
    watched = notice(watcher.verfer.qb64, state)
    witnessed = notice(w.verfer.qb64, state)
    own = notice(c.pre, state)
    scenarios.append(Scenario("trusted_sources_only",
                              "With keripy's trust policy on, a notice is kept only from the identifier itself, one"
                              " of its witnesses, or a watcher a local identifier configures; a stranger's is"
                              " refused.", [c.pre], lax=False, watchers=[watcher.verfer.qb64])
                     .event("inception", c.icp, "Accepted", **c.signed(c.icp))
                     .reply("stranger_notice", untrusted, "UntrustedKeyStateSource",
                            cigars=[stranger.sign(ser=untrusted.raw)])
                     .reply("watcher_notice", watched, "KeyStateAccepted", cigars=[watcher.sign(ser=watched.raw)])
                     .reply("witness_notice", witnessed, "KeyStateAccepted", cigars=[w.sign(ser=witnessed.raw)])
                     .reply("controller_notice", own, "KeyStateAccepted",
                            group=(c.pre, 0, c.icp.said, [c.keys[0].sign(ser=own.raw, index=0)]))
                     .record())

    # keripy keeps an older notice after a newer one, recorded as a divergence.
    c = Controller(60, w)
    newer = notice(w.verfer.qb64, c.state(c.icp, c.ixn), stamp=LATER)
    older = notice(w.verfer.qb64, c.state(c.icp), stamp=EARLIER)
    divergence = Scenario("older_notice_after_a_newer_one",
                          "A witness reports the state after the interaction, then, in a reply made earlier, the"
                          " state at the inception. keripy looks up the earlier reply from that source by the"
                          " reported event's SAID, which is not what it stores replies under, so it finds none,"
                          " compares no dates, and keeps the older report. The port compares the reply dates and"
                          " refuses it.", [c.pre])
    divergence.event("inception", c.icp, "Accepted", **c.signed(c.icp))
    divergence.reply("newer_notice", newer, "KeyStateAccepted", cigars=[w.sign(ser=newer.raw)])
    divergence.reply("older_notice", older, "KeyStateAccepted", cigars=[w.sign(ser=older.raw)])

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/core/routing.py"],
        "now": STAMP,
        "scenarios": scenarios,
        "divergence_older_notice": divergence.record(),
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "key-state-notices-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("key-state-notices-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
