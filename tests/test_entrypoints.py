"""Entry point tests for Standard v3 first-run readiness."""

import importlib
import os
from pathlib import Path
import unittest

from thirstys_waterfall.sovereign_binding import (
    execute_sovereign_protocol,
    get_sovereign_binding_status,
)


class TestSovereignBinding(unittest.TestCase):
    def test_binding_status_is_explicit(self):
        status = get_sovereign_binding_status()

        self.assertIn(status.available, {True, False})
        self.assertIsInstance(status.module, str)
        self.assertIn(status.backend, {"none", "thirsty-lang"})
        self.assertIs(status.as_dict()["available"], status.available)

    def test_missing_binding_does_not_crash_entrypoints(self):
        result = execute_sovereign_protocol({}, "TEST_PROTOCOL")

        status = get_sovereign_binding_status()
        if status.available:
            self.assertIsNotNone(result)
        else:
            self.assertIsNone(result)


class TestConsoleEntrypoint(unittest.TestCase):
    def test_cli_imports_and_exposes_main(self):
        cli = importlib.import_module("thirstys_waterfall.cli")

        self.assertTrue(callable(cli.main))
        self.assertTrue(callable(cli.main_sovereign_protocol))


class TestEnhancedThirstyLangPath(unittest.TestCase):
    def test_local_enhanced_thirsty_lang_path_can_be_loaded(self):
        local_path = next(
            (
                candidate
                for candidate in (
                    Path(r"T:\01-Projects\thirsty_lang_exploration_0754"),
                    Path(r"T:\00-Active\thirsty_lang_exploration_0754"),
                )
                if candidate.exists()
            ),
            Path(r"T:\01-Projects\thirsty_lang_exploration_0754"),
        )
        if not local_path.exists():
            self.skipTest("local enhanced Thirsty-Lang checkout is not present")

        previous = os.environ.get("THIRSTY_LANG_PATH")
        os.environ["THIRSTY_LANG_PATH"] = str(local_path)
        try:
            import thirstys_waterfall.sovereign_binding as binding

            binding = importlib.reload(binding)
            status = binding.get_sovereign_binding_status()
            result = binding.execute_sovereign_protocol({}, "INIT_PROTOCOL")

            self.assertTrue(status.available)
            self.assertEqual(status.backend, "thirsty-lang")
            self.assertEqual(status.source_path, str(local_path))
            self.assertEqual(result["verdict"], "ALLOW")
        finally:
            if previous is None:
                os.environ.pop("THIRSTY_LANG_PATH", None)
            else:
                os.environ["THIRSTY_LANG_PATH"] = previous
            import thirstys_waterfall.sovereign_binding as binding

            importlib.reload(binding)


if __name__ == "__main__":
    unittest.main()
