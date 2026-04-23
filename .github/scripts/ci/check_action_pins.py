# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

import re
import subprocess
import sys
from pathlib import Path

USES_RE = re.compile(r"^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([A-Za-z0-9._/-]+)(?:\s+#\s*(v[^\s]+))?\s*$")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

def iter_workflow_uses() -> list[tuple[Path, int, str, str, str | None]]:
  results: list[tuple[Path, int, str, str, str | None]] = []
  for workflow in sorted(Path(".github/workflows").glob("*.yml")):
    for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), start=1):
      match = USES_RE.match(line)
      if not match:
        continue
      owner_repo, ref, tag = match.groups()
      results.append((workflow, line_number, owner_repo, ref, tag))
  return results

def resolve_tag(owner_repo: str, tag: str) -> str:
  command = [
    "git",
    "ls-remote",
    f"https://github.com/{owner_repo}",
    f"refs/tags/{tag}",
    f"refs/tags/{tag}^{{}}",
  ]
  result = subprocess.run(command, check=False, capture_output=True, text=True)
  if result.returncode != 0:
    raise RuntimeError(f"failed to resolve {owner_repo}@{tag}: {result.stderr.strip()}")

  lines = [line for line in result.stdout.splitlines() if line.strip()]
  if not lines:
    raise RuntimeError(f"tag {tag} was not found for {owner_repo}")

  refs: dict[str, str] = {}
  for line in lines:
    sha, ref_name = line.split()
    refs[ref_name] = sha

  sha = refs.get(f"refs/tags/{tag}^{{}}", refs.get(f"refs/tags/{tag}"))
  if not sha:
    raise RuntimeError(f"tag {tag} was not found for {owner_repo}")

  if not FULL_SHA_RE.match(sha):
    raise RuntimeError(f"resolved ref for {owner_repo}@{tag} was not a full SHA: {sha}")
  return sha

def main() -> int:
  failures: list[str] = []

  for workflow, line_number, owner_repo, ref, tag in iter_workflow_uses():
    if owner_repo.startswith("./"):
      continue

    location = f"{workflow}:{line_number}"

    if not FULL_SHA_RE.match(ref):
      failures.append(f"{location}: {owner_repo}@{ref} is not pinned to a full 40-character SHA")
      continue

    if not tag:
      failures.append(f"{location}: {owner_repo}@{ref} is pinned but does not document an expected tag comment")
      continue

    try:
      resolved = resolve_tag(owner_repo, tag)
    except RuntimeError as exc:
      failures.append(f"{location}: {exc}")
      continue

    if resolved != ref:
      failures.append(
        f"{location}: {owner_repo} pinned to {ref} but {tag} currently resolves to {resolved}"
      )

  if failures:
    print("Action pin/drift check failed:", file=sys.stderr)
    for failure in failures:
      print(f"- {failure}", file=sys.stderr)
    return 1

  print("All GitHub Actions are fully pinned and match their documented tags.")
  return 0

if __name__ == "__main__":
  raise SystemExit(main())
