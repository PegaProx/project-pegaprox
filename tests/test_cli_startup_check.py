import unittest
from unittest.mock import patch

import pegaprox_multi_cluster as cli


class CliStartupCheckTests(unittest.TestCase):
    def test_check_startup_integrity_ok(self):
        with patch("pegaprox.api.validate_blueprint_modules", return_value=[]):
            self.assertTrue(cli.check_startup_integrity())

    def test_check_startup_integrity_fails_on_missing_modules(self):
        missing = ["pegaprox.api.reports"]
        with patch("pegaprox.api.validate_blueprint_modules", return_value=missing):
            self.assertFalse(cli.check_startup_integrity())


if __name__ == "__main__":
    unittest.main()
