import unittest
from scanner.core import get_ip_range, resolve_hostname, is_reachable, scan_parallel
from scanner.base import BaseScanner
import pytest

class TestCoreFunctions(unittest.TestCase):
    def test_get_ip_range(self):
        self.assertEqual(len(get_ip_range("192.168.1.0/30")), 4)
        self.assertIn("192.168.1.1", get_ip_range("192.168.1.0/30"))
        self.assertEqual(get_ip_range("invalid"), [])

    def test_resolve_hostname(self):
        self.assertEqual(resolve_hostname("localhost"), "127.0.0.1")
        self.assertIsNone(resolve_hostname("nonexistent.host"))

    def test_is_reachable(self):
        self.assertTrue(is_reachable("127.0.0.1"))
        self.assertFalse(is_reachable("10.255.255.1"))  # Không tồn tại

    def test_scan_parallel(self):
        targets = ["example.com", "google.com"]
        results = scan_parallel(targets)
        
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(v, dict) for v in results.values()))

    def test_invalid_targets(self):
        with self.assertRaises(ValueError):
            scanner = BaseScanner([])
