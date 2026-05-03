"""Run discover_targets in isolation and print the result.

Used to iteratively check whether discovery is finding the targets we need
without paying the full reachability cost.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from arbiter.llm.discover import discover_targets


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: probe_discover.py <package_path> <package_name>", file=sys.stderr)
        return 2
    package_path = Path(sys.argv[1]).resolve()
    package_name = sys.argv[2]
    targets = discover_targets(package_path, package_name)
    out = [t.model_dump(mode="json") for t in targets]
    print(json.dumps(out, indent=2))
    print(f"\n# {len(targets)} targets", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
