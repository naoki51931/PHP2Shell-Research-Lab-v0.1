import unittest
from app import assess


class VersionTests(unittest.TestCase):
    def test_vulnerable(self):
        self.assertEqual(assess("8.3.35")["status"], "potentially_vulnerable")

    def test_fixed(self):
        self.assertEqual(assess("8.3.36")["status"], "fixed_by_upstream_version")

    def test_unknown(self):
        self.assertEqual(assess("8.1.99")["status"], "unknown")

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            assess("8.3.35;echo bad")


if __name__ == "__main__":
    unittest.main()
