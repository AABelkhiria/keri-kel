"""Generates and checks key state adjudication vectors from the pinned keripy.

``src/adjudication.rs`` ports keripy's ``Adjudicator.adjudicate`` (``src/keri/app/watching.py``): it
compares the key state each watcher of an identifier last reported against the local state, and
decides whether they are consistent, whether some watchers lag, whether a threshold of watchers
agrees on a later state, or whether there is duplicity. Each case runs keripy's ``Adjudicator``,
unmodified, over a temporary keripy database holding the watchers' observations and the key state
notices they sent, and records the cue it emits. keripy's clock is pinned. keripy is pinned in
``pyproject.toml`` and ``uv.lock`` beside this file; run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/adjudication_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import datetime
import itertools
import json
import pathlib
import sys
from dataclasses import asdict
from types import SimpleNamespace

from keri.app import watching
from keri.core import eventing
from keri.core.coring import MtrDex, Saider
from keri.db import basing
from keri.help import helping

from kevery_keripy import STAMP, digest, signer
from reference import REFERENCE_SHA, REFERENCE_VERSION

GENERATED_ON = "2026-10-23"
DATABASES = itertools.count()


def state_after(events):
    """The key state keripy holds after accepting `events`, each `(serder, key)`."""
    db = basing.Baser(name=f"states-{next(DATABASES)}", temp=True, reopen=True)
    kevery = eventing.Kevery(db=db)
    for serder, key in events:
        kevery.processEvent(serder=serder, sigers=[key.sign(ser=serder.raw, index=0)])
    state = kevery.kevers[events[0][0].pre].state()
    db.close(clear=True)
    return state


def as_json(state):
    return json.dumps(asdict(state), separators=(",", ":"))


def adjudicate(local, reports, threshold):
    """Runs keripy's `Adjudicator` for `local`, with `reports` mapping each watcher to the state it
    last reported, or None when it reported none."""
    db = basing.Baser(name=f"adjudication-{next(DATABASES)}", temp=True, reopen=True)
    controller = "controller"
    watched = local.i
    for watcher, state in reports.items():
        db.obvs.put(keys=(controller, watcher, watched), val=basing.ObservedRecord(enabled=True))
        if state is not None:
            saider = Saider(qb64=state.d)
            db.ksns.pin(keys=(saider.qb64,), val=state)
            db.knas.pin(keys=(watched, watcher), val=saider)
    hab = SimpleNamespace(pre=controller, db=db, kevers={watched: SimpleNamespace(state=lambda: local)})
    adjudicator = watching.Adjudicator(hby=None, hab=hab)
    try:
        adjudicator.adjudicate(watched, threshold)
        outcome = {"raised": None}
        if adjudicator.cues:
            cue = adjudicator.cues.pull()
            named = cue.get("dups") or cue.get("aheads") or cue.get("behind") or cue.get("states") or []
            outcome.update(kind=cue["kin"],
                           watchers=sorted(cue["wids"]),
                           named=sorted([state.wit, state.state, state.sn, state.dig] for state in named))
            if "sn" in cue:
                outcome["sequence_number"] = cue["sn"]
        else:
            outcome["kind"] = None
    except ValueError as error:
        outcome = {"raised": type(error).__name__, "message": str(error)}
    db.close(clear=True)
    return outcome


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    key, nxt = signer(1), signer(2)
    icp = eventing.incept(keys=[key.verfer.qb64], ndigs=[digest(nxt)], code=MtrDex.Blake3_256)
    ixn1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1)
    fork1 = eventing.interact(pre=icp.pre, dig=icp.said, sn=1, data=[{"i": icp.pre}])
    ixn2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2)
    fork2 = eventing.interact(pre=icp.pre, dig=ixn1.said, sn=2, data=[{"i": icp.pre}])
    states = {
        "behind": state_after([(icp, key)]),
        "even": state_after([(icp, key), (ixn1, key)]),
        "duplicitous": state_after([(icp, key), (fork1, key)]),
        "ahead": state_after([(icp, key), (ixn1, key), (ixn2, key)]),
        "ahead_elsewhere": state_after([(icp, key), (ixn1, key), (fork2, key)]),
    }
    local = states["even"]
    w = [signer(30 + index, transferable=False).verfer.qb64 for index in range(3)]

    cases = []

    def case(name, note, reports, threshold=None):
        cases.append({
            "name": name,
            "note": note,
            "threshold": threshold,
            "reports": [{"watcher": watcher, "state": None if label is None else label}
                        for watcher, label in reports],
            "keripy": adjudicate(local, {watcher: None if label is None else states[label]
                                         for watcher, label in reports}, threshold),
        })

    case("all_even", "Every watcher reports the local state.",
         [(w[0], "even"), (w[1], "even"), (w[2], "even")])
    case("silent_watcher", "Two watchers report the local state and one reports nothing; the two decide.",
         [(w[0], "even"), (w[1], "even"), (w[2], None)])
    case("no_reports", "No watcher has reported anything.", [(w[0], None), (w[1], None)])
    case("one_behind", "One watcher reports an earlier state: it lags.",
         [(w[0], "even"), (w[1], "behind"), (w[2], "even")])
    case("one_duplicitous", "One watcher reports another event at the local sequence number.",
         [(w[0], "even"), (w[1], "duplicitous"), (w[2], "even")])
    case("duplicity_first", "Duplicity outweighs watchers ahead and behind.",
         [(w[0], "ahead"), (w[1], "duplicitous"), (w[2], "behind")])
    case("all_ahead", "Every watcher reports the same later state; with no threshold, all must agree.",
         [(w[0], "ahead"), (w[1], "ahead"), (w[2], "ahead")])
    case("enough_ahead", "Two of three watchers report the same later state, and two are enough.",
         [(w[0], "ahead"), (w[1], "ahead"), (w[2], "even")], threshold=2)
    case("too_few_ahead", "Two of three watchers report the same later state, but all three must agree;"
         " keripy decides nothing.", [(w[0], "ahead"), (w[1], "ahead"), (w[2], "even")])
    case("zero_threshold", "A threshold of zero means every watcher, as no threshold does: two of three ahead"
         " decide nothing.", [(w[0], "ahead"), (w[1], "ahead"), (w[2], "even")], threshold=0)
    case("ahead_hides_behind", "One watcher is ahead and one behind; keripy looks only at those ahead, which"
         " fall short of the threshold, and decides nothing.", [(w[0], "ahead"), (w[1], "behind"), (w[2], "even")])
    case("ahead_on_different_events", "Two watchers report different later events: duplicity among them.",
         [(w[0], "ahead"), (w[1], "ahead_elsewhere"), (w[2], "even")], threshold=1)
    case("threshold_above_the_watchers", "A threshold larger than the watcher set is refused.",
         [(w[0], "even"), (w[1], "even")], threshold=3)

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/app/watching.py"],
        "local": "even",
        "states": {label: as_json(state) for label, state in states.items()},
        "cases": cases,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "adjudication-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("adjudication-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
