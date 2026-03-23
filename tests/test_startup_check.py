import unittest

from pegaprox.api import validate_blueprint_modules


class StartupIntegrityCheckTests(unittest.TestCase):
    def test_validate_blueprint_modules_returns_empty_when_all_present(self):
        missing = validate_blueprint_modules()
        self.assertEqual(missing, [])

    def test_validate_blueprint_modules_reports_missing_module(self):
        def fake_resolver_with_missing(name):
            if name == "pegaprox.api.reports":
                return None
            return object()

        missing = validate_blueprint_modules(spec_resolver=fake_resolver_with_missing)
        self.assertEqual(missing, ["pegaprox.api.reports"])


if __name__ == "__main__":
    unittest.main()
