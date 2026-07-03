import json
import tempfile
import unittest
from pathlib import Path

import compile as compile_mod


class CompileTests(unittest.TestCase):
    def test_load_findings_reads_formatter_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_data_dir = compile_mod.DATA_DIR
            compile_mod.DATA_DIR = Path(tmp)
            try:
                date = "2026-01-02"
                swaggerhub = compile_mod.DATA_DIR / "swaggerhub"
                swaggerhub.mkdir(parents=True)
                (swaggerhub / f"{date}_matches.json").write_text(
                    json.dumps([{"source": "swaggerhub", "matched_value": "one"}]),
                    encoding="utf-8",
                )
                (compile_mod.DATA_DIR / f"formatters_{date}_matches.json").write_text(
                    json.dumps([{"source": "formatters", "matched_value": "two"}]),
                    encoding="utf-8",
                )

                findings = compile_mod.load_findings(date)
            finally:
                compile_mod.DATA_DIR = old_data_dir

        self.assertEqual([f["source"] for f in findings], ["swaggerhub", "formatters"])


if __name__ == "__main__":
    unittest.main()
