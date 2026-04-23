# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import generate_contributors


class GenerateContributorsTests(unittest.TestCase):
  def test_normalise_contributors_aggregates_by_email_and_filters_bots(self) -> None:
    contributors = generate_contributors.normalise_contributors(
      [
        ("Zen Dodd", "mail@steadytao.com"),
        ("Zen Dodd", "mail@steadytao.com"),
        ("Z Dodd", "mail@steadytao.com"),
        ("github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com"),
        ("Other Person", "other@example.com"),
      ]
    )

    self.assertEqual(
      contributors,
      [
        generate_contributors.Contributor(name="Zen Dodd", email="mail@steadytao.com", commits=3),
        generate_contributors.Contributor(name="Other Person", email="other@example.com", commits=1),
      ],
    )

  def test_render_contributors_emits_expected_header_and_entries(self) -> None:
    rendered = generate_contributors.render_contributors(
      [
        generate_contributors.Contributor(name="Zen Dodd", email="mail@steadytao.com", commits=3),
        generate_contributors.Contributor(name="Other Person", email="", commits=1),
      ]
    )

    self.assertTrue(
      rendered.startswith(
        "# This file is generated from Surveyor's reachable non-bot commit history.\n"
      )
    )
    self.assertIn("Zen Dodd <mail@steadytao.com>\n", rendered)
    self.assertTrue(rendered.endswith("Other Person\n"))


if __name__ == "__main__":
  unittest.main()
