# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
import subprocess
from pathlib import Path

SUPPORTED_SUFFIXES = {".go", ".py", ".sh"}
COPYRIGHT_RE = re.compile(r"Copyright(?:\s+\(c\))?\s+\d{4}(?:-\d{4})?\s+The Surveyor Authors")
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*Apache-2\.0")
WINDOW_SIZE = 8


def tracked_source_files() -> list[Path]:
  completed = subprocess.run(
    ["git", "ls-files"],
    check=True,
    capture_output=True,
    text=True,
  )
  files: list[Path] = []
  for line in completed.stdout.splitlines():
    path = Path(line)
    if path.suffix not in SUPPORTED_SUFFIXES:
      continue
    if path.parts and path.parts[0] in {"vendor", "dist"}:
      continue
    files.append(path)
  return sorted(files)


def discovered_source_files() -> list[Path]:
  files: list[Path] = []
  for path in Path(".").rglob("*"):
    if not path.is_file():
      continue
    if path.suffix not in SUPPORTED_SUFFIXES:
      continue
    if any(part in {"vendor", "dist", ".git"} for part in path.parts):
      continue
    files.append(path)
  return sorted(files)


def header_window(path: Path) -> str:
  lines = path.read_text(encoding="utf-8").splitlines()
  window: list[str] = []
  for index, line in enumerate(lines):
    if index == 0 and line.startswith("#!"):
      continue
    if not line.strip():
      continue
    window.append(line)
    if len(window) >= WINDOW_SIZE:
      break
  return "\n".join(window)


def main() -> int:
  files = tracked_source_files()
  if not files:
    files = discovered_source_files()
  if not files:
    print("No source files matched the header policy.")
    return 0

  failures: list[str] = []

  for path in files:
    window = header_window(path)
    if not COPYRIGHT_RE.search(window):
      failures.append(f"{path}: missing copyright notice")
    if not SPDX_RE.search(window):
      failures.append(f"{path}: missing SPDX-License-Identifier: Apache-2.0")

  if failures:
    print("File header policy violations:")
    for failure in failures:
      print(f"  - {failure}")
    return 1

  print(f"Verified file headers for {len(files)} tracked source file(s).")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
