"""The keripy commit and version the generator runs against, read from the pinned dependency in uv.lock."""

import pathlib
import re
import tomllib

_LOCK = pathlib.Path(__file__).resolve().parent / "uv.lock"


def _pinned() -> tuple[str, str]:
    lock = tomllib.loads(_LOCK.read_text(encoding="utf-8"))
    for package in lock.get("package", []):
        if package.get("name") != "keri":
            continue
        source = package.get("source", {}).get("git", "")
        match = re.search(r"#([0-9a-f]{40})$", source)
        if match is None:
            raise RuntimeError(f"uv.lock does not pin keri to a commit: {source!r}")
        return match.group(1), str(package["version"])
    raise RuntimeError("uv.lock has no keri package")


REFERENCE_SHA, REFERENCE_VERSION = _pinned()
