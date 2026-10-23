"""Generates and checks endpoint reply vectors from the pinned keripy.

``src/endpoint.rs`` ports keripy's handling of the replies that say where an identifier is served:
``/end/role/add`` and ``/end/role/cut``, in which a controller grants or withdraws a role (witness,
watcher, mailbox, ...) to an endpoint identifier, and ``/loc/scheme``, in which an endpoint gives its
URL for a scheme. ``Revery.processReply`` verifies each reply and ``Kevery.processReplyEndRole`` or
``processReplyLocScheme`` decides whether to keep it. Each scenario offers keripy, unmodified,
events and replies in some order, the way keripy's parser would, processes event and reply
escrows after each, and records what keripy then holds, with ``kevery_keripy.Scenario``. keripy's
clock is pinned. keripy is pinned in ``pyproject.toml`` and ``uv.lock`` beside this file; run from
the repository root:

    uv sync --locked --project tools/reference-vectors
    DYLD_LIBRARY_PATH=/opt/homebrew/lib uv run --project tools/reference-vectors \\
        python tools/reference-vectors/endpoints_keripy.py --write   # or --check

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
THIRD = "2021-01-01T00:00:03.000000+00:00"


def end_role(action, cid, role, eid, stamp=STAMP):
    return eventing.reply(route=f"/end/role/{action}", data=dict(cid=cid, role=role, eid=eid), stamp=stamp)


def location(eid, scheme, url, stamp=STAMP):
    return eventing.reply(route="/loc/scheme", data=dict(eid=eid, scheme=scheme, url=url), stamp=stamp)


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
    watcher = signer(30, transferable=False)
    stranger = signer(39, transferable=False)
    wid = watcher.verfer.qb64
    scenarios = []

    # A controller grants and withdraws a role.
    key, icp = controller(1)
    add = end_role("add", icp.pre, "watcher", wid, stamp=FIRST)
    cut = end_role("cut", icp.pre, "watcher", wid, stamp=SECOND)
    late_add = end_role("add", icp.pre, "watcher", wid, stamp=FIRST)
    mailbox = end_role("add", icp.pre, "mailbox", wid, stamp=FIRST)
    scenarios.append(Scenario("role_granted_and_withdrawn",
                              "A controller makes a watcher its watcher, then withdraws the role in a later reply."
                              " The same withdrawal offered again is kept again; the grant offered again, being"
                              " older, is not. Another role for the same endpoint is kept apart.",
                              [icp.pre])
                     .event("controller_inception", icp, "Accepted", sigers=[key.sign(ser=icp.raw, index=0)])
                     .reply("grant", add, "EndRoleAccepted", group=group(key, icp, add))
                     .reply("withdrawal", cut, "EndRoleAccepted", group=group(key, icp, cut))
                     .reply("withdrawal_again", cut, "EndRoleAccepted", group=group(key, icp, cut))
                     .reply("grant_again", late_add, "UnverifiedReply", group=group(key, icp, late_add))
                     .reply("mailbox_grant", mailbox, "EndRoleAccepted", group=group(key, icp, mailbox))
                     .record())

    # Grants that are not the controller's own.
    key, icp = controller(10)
    by_endpoint = end_role("add", icp.pre, "watcher", wid)
    unknown_role = end_role("add", icp.pre, "boss", wid)
    scenarios.append(Scenario("grants_keripy_refuses",
                              "A grant signed by the endpoint rather than the controller is not kept, and one"
                              " naming a role keripy does not know is refused.", [icp.pre])
                     .event("controller_inception", icp, "Accepted", sigers=[key.sign(ser=icp.raw, index=0)])
                     .reply("grant_signed_by_the_endpoint", by_endpoint, "UnverifiedReply",
                            cigars=[watcher.sign(ser=by_endpoint.raw)])
                     .reply("grant_of_an_unknown_role", unknown_role, "InvalidReply",
                            group=group(key, icp, unknown_role))
                     .record())

    # A grant before the controller's inception.
    key, icp = controller(20)
    add = end_role("add", icp.pre, "watcher", wid)
    scenarios.append(Scenario("grant_before_the_controller",
                              "A grant arrives before the controller's inception; it waits in the reply escrow and"
                              " is kept once the inception is accepted.", [icp.pre])
                     .reply("grant", add, "Escrowed:UnverifiedReply", group=group(key, icp, add))
                     .event("controller_inception", icp, "Accepted", sigers=[key.sign(ser=icp.raw, index=0)])
                     .record())

    # An endpoint gives its locations.
    http = location(wid, "http", "http://watcher.example:5642/", stamp=FIRST)
    moved = location(wid, "http", "http://watcher.example:5643/", stamp=SECOND)
    tcp = location(wid, "tcp", "tcp://watcher.example:5632/", stamp=FIRST)
    by_stranger = location(wid, "http", "http://elsewhere.example/", stamp=THIRD)
    mismatch = location(wid, "https", "http://watcher.example:5642/", stamp=THIRD)
    scenarios.append(Scenario("endpoint_locations",
                              "An endpoint gives its HTTP URL, then a newer one, which replaces it; offered again,"
                              " the newer one is not newer than itself and is not kept again. Its TCP URL is"
                              " kept apart. A location signed by someone else is not kept, and one whose URL"
                              " does not use its scheme is refused.", [wid])
                     .reply("http_location", http, "LocationAccepted", cigars=[watcher.sign(ser=http.raw)])
                     .reply("moved_http_location", moved, "LocationAccepted", cigars=[watcher.sign(ser=moved.raw)])
                     .reply("moved_http_location_again", moved, "UnverifiedReply",
                            cigars=[watcher.sign(ser=moved.raw)])
                     .reply("tcp_location", tcp, "LocationAccepted", cigars=[watcher.sign(ser=tcp.raw)])
                     .reply("location_signed_by_another", by_stranger, "UnverifiedReply",
                            cigars=[stranger.sign(ser=by_stranger.raw)])
                     .reply("location_with_another_scheme", mismatch, "InvalidReply",
                            cigars=[watcher.sign(ser=mismatch.raw)])
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

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "endpoints-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("endpoints-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
