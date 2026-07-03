import tempfile
import unittest
from pathlib import Path

import utils.deduplication as dedup


class DeduplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_file = dedup._HASHES_FILE
        self.old_seen = dedup._seen
        self.old_loaded = dedup._loaded
        dedup._HASHES_FILE = Path(self.tmp.name) / "seen_hashes.json"
        dedup._seen = set()
        dedup._loaded = False

    def tearDown(self):
        dedup._HASHES_FILE = self.old_file
        dedup._seen = self.old_seen
        dedup._loaded = self.old_loaded
        self.tmp.cleanup()

    def test_seen_key_includes_matched_value(self):
        dedup.mark_seen("github_search", "owner/repo/.env", "generic_api_key", "secret-one")

        self.assertTrue(dedup.is_seen("github_search", "owner/repo/.env", "generic_api_key", "secret-one"))
        self.assertFalse(dedup.is_seen("github_search", "owner/repo/.env", "generic_api_key", "secret-two"))


if __name__ == "__main__":
    unittest.main()
