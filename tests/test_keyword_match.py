import unittest

from utils.keyword_match import find_keyword, keyword_in_text


class KeywordMatchTests(unittest.TestCase):
    def test_short_keyword_does_not_match_inside_bank_names(self):
        for text in ("isbank", "axisbankupi", "solarisbank", "cobis-banrural", "IS-BandaAncha"):
            with self.subTest(text=text):
                self.assertFalse(keyword_in_text(text, "isban"))

    def test_short_keyword_matches_token_forms(self):
        for text in ("isban", "isban-prod", "isban_api", "legacy isban service"):
            with self.subTest(text=text):
                self.assertTrue(keyword_in_text(text, "isban"))

    def test_domain_keyword_still_matches_urls(self):
        self.assertTrue(keyword_in_text("https://santander.com.br/api", "santander.com.br"))
        self.assertTrue(keyword_in_text("https://api.santander.com.br/v1", "santander.com.br"))
        self.assertFalse(keyword_in_text("https://fake-santander.com.br.evil/api", "santander.com.br"))

    def test_find_keyword_returns_first_token_match(self):
        self.assertEqual(find_keyword("axisbankupi isban-prod", ["isban", "santander"]), "isban")


if __name__ == "__main__":
    unittest.main()
