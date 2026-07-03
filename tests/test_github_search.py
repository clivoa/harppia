import unittest

from scanners.github_search import _content_key, _raw_url


class GitHubSearchTests(unittest.TestCase):
    def test_raw_url_uses_default_branch_not_blob_sha(self):
        item = {
            "sha": "blob-sha",
            "path": "config/app.env",
            "repository": {
                "name": "repo",
                "full_name": "owner/repo",
                "default_branch": "main",
                "owner": {"login": "owner"},
            },
        }

        self.assertEqual(
            _raw_url(item),
            "https://raw.githubusercontent.com/owner/repo/main/config/app.env",
        )

    def test_content_key_is_stable_file_path(self):
        item = {"path": ".env", "repository": {"full_name": "owner/repo"}}

        self.assertEqual(_content_key(item), "owner/repo/.env")


if __name__ == "__main__":
    unittest.main()
