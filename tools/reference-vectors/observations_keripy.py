"""Generates and checks watcher observation vectors from the pinned keripy.

``src/observation.rs`` ports keripy's handling of watcher registrations: ``/watcher/{watcher}/add``
and ``/watcher/{watcher}/cut`` replies, in which a controller asks a watcher to start or stop
observing an identifier, optionally giving an OOBI for it. ``Revery.processReply`` verifies each
reply and ``Kevery.processReplyAddWatched`` decides whether to keep it. Each scenario offers keripy,
unmodified, events and replies in some order, the way keripy's parser would, processes event and
reply escrows after each, and records what keripy then holds, with ``kevery_keripy.Scenario``.
keripy's clock is pinned. keripy is pinned in ``pyproject.toml`` and ``uv.lock`` beside this file;
run from the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/observations_keripy.py --write   # or --check

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
FIRST = "2021-01-01T00:00:01.000000+00:00"
SECOND = "2021-01-01T00:00:02.000000+00:00"


def observation(action, watcher, cid, oid, oobi=None, stamp=STAMP):
    data = dict(cid=cid, oid=oid)
    if oobi is not None:
        data["oobi"] = oobi
    return eventing.reply(route=f"/watcher/{watcher}/{action}", data=data, stamp=stamp)


def controller(seed):
    keys = [signer(seed), signer(seed + 1)]
    icp = eventing.incept(keys=[keys[0].verfer.qb64], ndigs=[digest(keys[1])], code=MtrDex.Blake3_256)
    return keys[0], icp


def group(key, icp, reply):
    """A controller's signature group over `reply`, from its inception's keys."""
    return (icp.pre, 0, icp.said, [key.sign(ser=reply.raw, index=0)])


def main():
    helping.nowIso8601 = lambda: STAMP
    helping.nowUTC = lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc)
    w = signer(30, transferable=False)
    other = signer(31, transferable=False)
    wid, other_id = w.verfer.qb64, other.verfer.qb64
    _, observed = controller(60)
    _, second = controller(62)
    oid, second_oid = observed.pre, second.pre
    oobi = f"http://witness.example:5642/oobi/{oid}/witness"
    scenarios = []

    # A controller starts and stops a watcher's observation.
    key, icp = controller(1)
    add = observation("add", wid, icp.pre, oid, oobi=oobi, stamp=FIRST)
    cut = observation("cut", wid, icp.pre, oid, stamp=SECOND)
    late_add = observation("add", wid, icp.pre, oid, stamp=FIRST)
    scenarios.append(Scenario("observation_started_and_stopped",
                              "A controller asks a watcher to observe an identifier, giving an OOBI for it, which"
                              " is queued; it stops the observation in a later reply. Offered again, the stop is"
                              " not newer than itself and the start is older, so neither is kept again.",
                              [icp.pre, wid])
                     .event("controller_inception", icp, "Accepted", sigers=[key.sign(ser=icp.raw, index=0)])
                     .reply("start", add, "ObservationAccepted", group=group(key, icp, add))
                     .reply("stop", cut, "ObservationAccepted", group=group(key, icp, cut))
                     .reply("stop_again", cut, "UnverifiedReply", group=group(key, icp, cut))
                     .reply("start_again", late_add, "UnverifiedReply", group=group(key, icp, late_add))
                     .record())

    # Registrations that are not the controller's own.
    key, icp = controller(10)
    by_watcher = observation("add", wid, icp.pre, oid)
    scenarios.append(Scenario("registration_signed_by_the_watcher",
                              "A registration signed by the watcher rather than the controller is not kept.",
                              [icp.pre, wid])
                     .event("controller_inception", icp, "Accepted", sigers=[key.sign(ser=icp.raw, index=0)])
                     .reply("start_signed_by_the_watcher", by_watcher, "UnverifiedReply",
                            cigars=[w.sign(ser=by_watcher.raw)])
                     .record())

    # A registration before the controller's inception.
    key, icp = controller(20)
    add = observation("add", wid, icp.pre, oid)
    scenarios.append(Scenario("registration_before_the_controller",
                              "A registration arrives before the controller's inception; it waits in the reply"
                              " escrow and is kept once the inception is accepted.", [icp.pre, wid])
                     .reply("start", add, "Escrowed:UnverifiedReply", group=group(key, icp, add))
                     .event("controller_inception", icp, "Accepted", sigers=[key.sign(ser=icp.raw, index=0)])
                     .record())

    # Observations kept apart.
    key, icp = controller(40)
    first = observation("add", wid, icp.pre, oid)
    second_observed = observation("add", wid, icp.pre, second_oid)
    other_watcher = observation("add", other_id, icp.pre, oid)
    scenarios.append(Scenario("observations_kept_apart",
                              "Observations of two identifiers by one watcher, and of one identifier by two"
                              " watchers, are kept apart.", [icp.pre, wid, other_id])
                     .event("controller_inception", icp, "Accepted", sigers=[key.sign(ser=icp.raw, index=0)])
                     .reply("first_observed", first, "ObservationAccepted", group=group(key, icp, first))
                     .reply("second_observed", second_observed, "ObservationAccepted",
                            group=group(key, icp, second_observed))
                     .reply("other_watcher", other_watcher, "ObservationAccepted",
                            group=group(key, icp, other_watcher))
                     .record())

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/core/routing.py"],
        "now": STAMP,
        "scenarios": scenarios,
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "observations-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("observations-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
