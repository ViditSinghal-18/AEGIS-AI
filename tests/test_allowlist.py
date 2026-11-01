"""Allowlist guard unit checks (no network)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import is_target_allowed, require_allowed_target


class AllowlistTests(unittest.TestCase):
    def test_localhost_allowed(self) -> None:
        self.assertTrue(is_target_allowed("localhost"))
        self.assertTrue(is_target_allowed("http://127.0.0.1:3000"))

    def test_public_host_blocked(self) -> None:
        self.assertFalse(is_target_allowed("example.com"))
        with self.assertRaises(PermissionError):
            require_allowed_target("scanme.nmap.org")


if __name__ == "__main__":
    unittest.main()
