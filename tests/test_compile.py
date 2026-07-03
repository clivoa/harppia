import json
import tempfile
import unittest
from pathlib import Path

import compile as compile_mod


class CompileTests(unittest.TestCase):
    def test_load_findings_all_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_data_dir = compile_mod.DATA_DIR
            compile_mod.DATA_DIR = Path(tmp)
            try:
                date = "2026-01-02"

                def write(subpath, source, value):
                    p = compile_mod.DATA_DIR / subpath
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(
                        json.dumps([{"source": source, "matched_value": value}]),
                        encoding="utf-8",
                    )

                write(f"swaggerhub/{date}_matches.json",   "swaggerhub",   "one")
                write(f"formatters_{date}_matches.json",   "formatters",   "two")
                write(f"sourcegraph/{date}_matches.json",  "sourcegraph",  "three")
                write(f"npm/{date}_matches.json",          "npm",          "four")
                write(f"pastebin/{date}_matches.json",     "pastebin",     "five")

                findings = compile_mod.load_findings(date)
            finally:
                compile_mod.DATA_DIR = old_data_dir

        sources = [f["source"] for f in findings]
        self.assertIn("swaggerhub", sources)
        self.assertIn("formatters", sources)
        self.assertIn("sourcegraph", sources)
        self.assertIn("npm", sources)
        self.assertIn("pastebin", sources)

    def test_missing_files_are_silently_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_data_dir = compile_mod.DATA_DIR
            compile_mod.DATA_DIR = Path(tmp)
            try:
                findings = compile_mod.load_findings("2099-01-01")
            finally:
                compile_mod.DATA_DIR = old_data_dir

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
