"""After `novpn add`, sites that already flagged the VPN keep it in cookies, so the CLI says how to clear them."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import novpn  # noqa: E402


class CookieHintTest(unittest.TestCase):
    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(novpn, "daemon_state", return_value=None):
            code = novpn.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"NOVPN_REGISTRY": str(Path(tmp.name) / "domains.txt"),
                                               "NO_COLOR": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_hint_names_every_added_site_with_a_chrome_link(self):
        hint = novpn.cookie_hint(["ozon.ru", "avito.ru"])
        self.assertIn("cookies", hint)
        self.assertIn("chrome://settings/content/all?searchSubpage=ozon.ru", hint)
        self.assertIn("chrome://settings/content/all?searchSubpage=avito.ru", hint)
        self.assertIn("Safari", hint)

    def test_hint_is_empty_without_sites(self):
        self.assertEqual(novpn.cookie_hint([]), "")

    def test_add_prints_the_hint_for_new_sites_only(self):
        code, out, _ = self.cli("add", "ozon.ru")
        self.assertEqual(code, 0)
        self.assertIn("searchSubpage=ozon.ru", out)
        code, out, _ = self.cli("add", "ozon.ru")
        self.assertEqual(code, 0)
        self.assertNotIn("searchSubpage", out)

    def test_rm_does_not_print_the_hint(self):
        self.cli("add", "ozon.ru")
        _, out, _ = self.cli("rm", "ozon.ru")
        self.assertNotIn("cookies", out)


if __name__ == "__main__":
    unittest.main()
