# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT_PATH = ROOT / "CONTRIBUTORS"

HEADER_LINES = [
  "# This file is generated from Surveyor's reachable non-bot commit history.",
  "# Do not edit it manually. Regenerate it with:",
  "#   python .github/scripts/release/generate_contributors.py --write",
  "#",
  "# CONTRIBUTORS is a recognition list. It is not the copyright-authority file.",
  "# See AUTHORS for the curated copyright-purpose author list.",
]


@dataclass(frozen=True)
class Contributor:
  name: str
  email: str
  commits: int


def parse_args(argv: list[str]) -> argparse.Namespace:
  parser = argparse.ArgumentParser(
    description="Generate or verify the root CONTRIBUTORS file from git history."
  )
  mode = parser.add_mutually_exclusive_group()
  mode.add_argument("--write", action="store_true", help="Write CONTRIBUTORS to disk.")
  mode.add_argument("--check", action="store_true", help="Fail if CONTRIBUTORS is stale.")
  return parser.parse_args(argv)


def is_bot_identity(name: str, email: str) -> bool:
  folded_name = name.casefold()
  folded_email = email.casefold()
  return "[bot]" in folded_name or "[bot]" in folded_email


def collect_contributor_rows(repo_root: Path) -> list[tuple[str, str]]:
  command = [
    "git",
    "-C",
    str(repo_root),
    "log",
    "--no-merges",
    "--format=%aN%x00%aE",
    "HEAD",
  ]
  result = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8")
  if result.returncode != 0:
    raise RuntimeError(f"failed to read git history: {result.stderr.strip()}")

  rows: list[tuple[str, str]] = []
  for line in result.stdout.splitlines():
    if not line:
      continue
    try:
      name, email = line.split("\x00", maxsplit=1)
    except ValueError as exc:
      raise RuntimeError(f"unexpected git log output line: {line!r}") from exc
    rows.append((name.strip(), email.strip()))
  return rows


def normalise_contributors(rows: list[tuple[str, str]]) -> list[Contributor]:
  buckets: dict[str, dict[str, object]] = {}

  for name, email in rows:
    if is_bot_identity(name, email):
      continue

    clean_name = name.strip()
    clean_email = email.strip()
    if not clean_name and not clean_email:
      continue

    key = clean_email.casefold() if clean_email else f"name:{clean_name.casefold()}"
    bucket = buckets.setdefault(
      key,
      {
        "commits": 0,
        "names": Counter(),
        "email": clean_email,
      },
    )
    bucket["commits"] = int(bucket["commits"]) + 1
    if clean_name:
      bucket["names"][clean_name] += 1
    if clean_email and not bucket["email"]:
      bucket["email"] = clean_email

  contributors: list[Contributor] = []
  for bucket in buckets.values():
    names: Counter[str] = bucket["names"]
    if names:
      name = sorted(names.items(), key=lambda item: (-item[1], item[0].casefold()))[0][0]
    else:
      name = "Unknown Contributor"
    email = str(bucket["email"])
    contributors.append(
      Contributor(
        name=name,
        email=email,
        commits=int(bucket["commits"]),
      )
    )

  return sorted(
    contributors,
    key=lambda contributor: (
      -contributor.commits,
      contributor.name.casefold(),
      contributor.email.casefold(),
    ),
  )


def render_contributors(contributors: list[Contributor]) -> str:
  body_lines = HEADER_LINES.copy()
  body_lines.append("")

  for contributor in contributors:
    if contributor.email:
      body_lines.append(f"{contributor.name} <{contributor.email}>")
    else:
      body_lines.append(contributor.name)

  return "\n".join(body_lines) + "\n"


def expected_contents(repo_root: Path) -> str:
  return render_contributors(normalise_contributors(collect_contributor_rows(repo_root)))


def main(argv: list[str]) -> int:
  args = parse_args(argv)
  expected = expected_contents(ROOT)

  if args.write:
    OUTPUT_PATH.write_text(expected, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.relative_to(ROOT)}")
    return 0

  if args.check:
    actual = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else ""
    if actual != expected:
      print(
        "CONTRIBUTORS is stale. Regenerate it with "
        "`python .github/scripts/release/generate_contributors.py --write`.",
        file=sys.stderr,
      )
      return 1
    print("CONTRIBUTORS matches the reachable non-bot commit history.")
    return 0

  sys.stdout.write(expected)
  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv[1:]))
