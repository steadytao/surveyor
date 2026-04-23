# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

import html
import os
import sys
from pathlib import Path
from report_payload import PayloadError, load_report_payload

def append_summary(lines: list[str]) -> None:
  summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
  if summary_path:
    Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")

def main() -> int:
  try:
    payload = load_report_payload("goreportcard-response.html")
  except PayloadError as exc:
    message = str(exc)
    append_summary(
      [
        "# Go Report Card",
        f"- Repository: `{os.environ['REPO']}`",
        "- Result: failed",
        "",
        "## Why this failed",
        f"- {message}",
      ]
    )
    print(message, file=sys.stderr)
    return 1

  expected_repo = os.environ["REPO"]
  repo = payload.get("repo") or expected_repo
  grade = payload.get("grade", "unknown")
  version = payload.get("version", "unknown")
  issues = int(payload.get("issues", 0))
  files = int(payload.get("files", 0))
  did_error = bool(payload.get("did_error", False))
  last_refresh = payload.get("last_refresh", "unknown")
  report_url = f"https://goreportcard.com/report/{repo}"
  max_issues = int(os.environ["MAX_ISSUES"])

  print(f"Repository: {repo}")
  print(f"Version: {version}")
  print(f"Grade: {grade}")
  print(f"Files checked: {files}")
  print(f"Issues: {issues}")
  print(f"Last refresh: {last_refresh}")

  if repo != expected_repo:
    message = f"Go Report Card returned data for {repo}, expected {expected_repo}."
    append_summary(
      [
        "# Go Report Card",
        f"- Repository: `{expected_repo}`",
        "- Result: failed",
        "",
        "## Why this failed",
        f"- {message}",
      ]
    )
    print(message, file=sys.stderr)
    return 1

  if did_error:
    message = "Go Report Card reported an error during analysis."
    append_summary(
      [
        "# Go Report Card",
        f"- Repository: `{repo}`",
        f"- Report: {report_url}",
        "- Result: failed",
        "",
        "## Why this failed",
        f"- {message}",
      ]
    )
    print(message, file=sys.stderr)
    return 1

  issue_details = []
  for check in payload.get("checks", []):
    check_name = check.get("name", "unknown")
    for file_summary in check.get("file_summaries", []):
      filename = file_summary.get("filename", "<unknown file>")
      for error in file_summary.get("errors", []):
        line_number = error.get("line_number")
        message = html.unescape(error.get("error_string", "")).strip()
        if line_number:
          issue_details.append(f"{check_name}: {filename}:{line_number}: {message}")
        else:
          issue_details.append(f"{check_name}: {filename}: {message}")

  summary_lines = [
    "# Go Report Card",
    f"- Repository: `{repo}`",
    f"- Report: {report_url}",
    f"- Version: `{version}`",
    f"- Grade: `{grade}`",
    f"- Files checked: `{files}`",
    f"- Issues: `{issues}`",
    f"- Last refresh: `{last_refresh}`",
    "",
  ]

  should_fail = issues > max_issues

  if should_fail:
    print(
      f"Go Report Card issue budget exceeded: {issues} issue(s), allowed {max_issues}.",
      file=sys.stderr,
    )
    if issue_details:
      print("Detailed findings:", file=sys.stderr)
      for detail in issue_details:
        print(f"- {detail}", file=sys.stderr)
      summary_lines.append("## Findings")
      for detail in issue_details:
        summary_lines.append(f"- `{detail}`")
    else:
      summary_lines.append("## Findings")
      summary_lines.append("- Go Report Card reported issues but did not include per-file details.")
  else:
    summary_lines.append("## Result")
    summary_lines.append("- Go Report Card returned zero issues.")
    if issue_details:
      print("Go Report Card returned findings within the allowed budget:")
      for detail in issue_details:
        print(f"- {detail}")
    else:
      print("Go Report Card returned zero detailed findings.")

  append_summary(summary_lines)
  return 1 if should_fail else 0

if __name__ == "__main__":
  raise SystemExit(main())
