# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

import json
import re
import sys
from pathlib import Path

class PayloadError(Exception):
  pass

def parse_refresh_redirect(refresh_response: str) -> str:
  try:
    payload = json.loads(refresh_response)
  except json.JSONDecodeError as exc:
    raise PayloadError(f"Failed to decode refresh response: {exc}") from exc

  redirect = payload.get("redirect")
  if not redirect:
    raise PayloadError("Go Report Card refresh response did not include a redirect target.")
  if not isinstance(redirect, str):
    raise PayloadError("Go Report Card refresh redirect was not a string.")
  if not redirect.startswith("/report/"):
    raise PayloadError(f"Unexpected Go Report Card refresh redirect: {redirect}")
  return redirect

def extract_report_payload(page: str) -> dict:
  match = re.search(r"var\s+response\s*=\s*(\{.*?\})\s*;", page, re.DOTALL)
  if not match:
    raise PayloadError("Go Report Card response payload was not found in the returned HTML.")

  try:
    payload = json.loads(match.group(1))
  except json.JSONDecodeError as exc:
    raise PayloadError(f"Failed to decode Go Report Card payload: {exc}") from exc
  if not isinstance(payload, dict):
    raise PayloadError("Go Report Card payload was not a JSON object.")
  return payload

def load_report_payload(path: str | Path) -> dict:
  page = Path(path).read_text(encoding="utf-8")
  return extract_report_payload(page)

def extract_last_refresh(path: str | Path) -> str:
  payload = load_report_payload(path)
  value = payload.get("last_refresh", "")
  return value if isinstance(value, str) else ""

def main(argv: list[str]) -> int:
  if len(argv) < 2:
    print("usage: report_payload.py <parse-refresh-redirect|extract-last-refresh>", file=sys.stderr)
    return 1

  command = argv[1]
  try:
    if command == "parse-refresh-redirect":
      print(parse_refresh_redirect(Path(argv[2]).read_text(encoding="utf-8")))
      return 0

    if command == "extract-last-refresh":
      print(extract_last_refresh(argv[2]))
      return 0
  except (IndexError, PayloadError) as exc:
    print(str(exc), file=sys.stderr)
    return 1

  print(f"unknown command: {command}", file=sys.stderr)
  return 1

if __name__ == "__main__":
  raise SystemExit(main(sys.argv))
