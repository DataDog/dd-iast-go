# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2026-present Datadog, Inc.
#
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# Run: python3 .github/merge-coverage.py <profile> [<profile> ...]

import sys
from collections import defaultdict
from pathlib import Path


def position(
    item: tuple[tuple[str, int], int],
) -> tuple[str, int, int, int, int, int]:
    (location, statements), _ = item
    path, span = location.rsplit(":", 1)
    start, end = span.split(",")
    start_line, start_column = map(int, start.split("."))
    end_line, end_column = map(int, end.split("."))
    return path, start_line, start_column, end_line, end_column, statements


def main() -> None:
    """Merge atomic profiles without losing hits from other test runs."""
    if len(sys.argv) < 2:
        raise SystemExit("expected at least one Go coverage profile")

    counts: defaultdict[tuple[str, int], int] = defaultdict(int)
    for name in sys.argv[1:]:
        lines = Path(name).read_text(encoding="utf-8").splitlines()
        if not lines or lines[0] != "mode: atomic":
            raise SystemExit(f"{name}: expected an atomic Go coverage profile")
        for line in lines[1:]:
            location, statements, count = line.split()
            counts[(location, int(statements))] += int(count)

    with Path("coverage.merged.txt").open("w", encoding="utf-8") as output:
        output.write("mode: atomic\n")
        for (location, statements), count in sorted(counts.items(), key=position):
            output.write(f"{location} {statements} {count}\n")


if __name__ == "__main__":
    main()
