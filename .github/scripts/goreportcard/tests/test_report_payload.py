# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

import tempfile
import unittest
from pathlib import Path

from report_payload import (
  PayloadError,
  extract_last_refresh,
  extract_report_payload,
  parse_refresh_redirect,
)

class ParseRefreshRedirectTests(unittest.TestCase):
  def test_rejects_invalid_json(self) -> None:
    with self.assertRaises(PayloadError):
      parse_refresh_redirect("{")

  def test_rejects_missing_redirect(self) -> None:
    with self.assertRaises(PayloadError):
      parse_refresh_redirect("{}")

  def test_rejects_unexpected_redirect_shape(self) -> None:
    with self.assertRaises(PayloadError):
      parse_refresh_redirect('{"redirect":"https://example.com/report"}')

  def test_accepts_relative_report_redirect(self) -> None:
    self.assertEqual(
      parse_refresh_redirect('{"redirect":"/report/github.com/example/repo"}'),
      "/report/github.com/example/repo",
    )

class ExtractReportPayloadTests(unittest.TestCase):
  def test_rejects_missing_payload(self) -> None:
    with self.assertRaises(PayloadError):
      extract_report_payload("<html></html>")

  def test_rejects_invalid_json(self) -> None:
    with self.assertRaises(PayloadError):
      extract_report_payload("var response = {oops};")

  def test_extracts_payload(self) -> None:
    payload = extract_report_payload('var response = {"repo":"github.com/example/repo","issues":0};')
    self.assertEqual(payload["repo"], "github.com/example/repo")
    self.assertEqual(payload["issues"], 0)

  def test_extracts_last_refresh_from_file(self) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
      path = Path(temp_dir) / "report.html"
      path.write_text(
        'var response = {"repo":"github.com/example/repo","last_refresh":"2026-04-19T00:00:00Z"};',
        encoding="utf-8",
      )
      self.assertEqual(extract_last_refresh(path), "2026-04-19T00:00:00Z")

if __name__ == "__main__":
  unittest.main()
