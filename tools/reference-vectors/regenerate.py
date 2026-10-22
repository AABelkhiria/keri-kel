"""Runs every fixture generator against the pinned keripy; with --check, fails if any fixture changed.

Run from the repository root:

    uv sync --locked --project tools/reference-vectors
    uv run --locked --project tools/reference-vectors python tools/reference-vectors/regenerate.py --check
"""

import pathlib
import runpy
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SKIPPED = {"reference.py", "regenerate.py"}


def main():
    sys.path.insert(0, str(HERE))
    for generator in sorted(HERE.glob("*.py")):
        if generator.name in SKIPPED:
            continue
        sys.argv = [str(generator), "--write"]
        runpy.run_path(str(generator), run_name="__main__")
    if "--check" in sys.argv[1:] or "--check" in sys.orig_argv:
        result = subprocess.run(["git", "diff", "--exit-code", "--stat", "--", "fixtures"], cwd=ROOT, check=False)
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
