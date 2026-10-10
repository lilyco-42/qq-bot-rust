import importlib.util
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch
p = Path(__file__).with_name("readonly_gateway.py")
spec = importlib.util.spec_from_file_location("readonly_gateway", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class GatewayTest(TestCase):
    def test_explicit_allowlist(self):
        self.assertEqual(len(m.TOOLS), 5)
        self.assertNotIn("bash", [x["name"] for x in m.TOOLS])
        for name in ("write", "exec", "github_issue_create", "file_edit"):
            with self.assertRaises(ValueError):
                m.dispatch(name, {})
    def test_ssrf_denied(self):
        for url in ("http://127.0.0.1/", "https://10.0.0.1/", "https://localhost/",
                    "file:///etc/passwd", "https://github.com@localhost/",
                    "https://github.com:8888/", "https://example.org/", "https://user:pass@github.com/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                m.check_url(url)
        self.assertEqual(m.check_url("https://github.com/sganggs/Stronghold-Protocol/issues/405"),
                         "https://github.com/sganggs/Stronghold-Protocol/issues/405")
    def test_issue_repo_restricted(self):
        with self.assertRaises(ValueError):
            m.issue_detail({"repo":"private/secret","number":1})
    def test_issue_search_expands_nicknames(self):
        def fake_gh(args, **kwargs):
            if args[0:2] == ["issue", "view"]:
                return '{"title":"叠不了层","url":"https://github.com/sganggs/Stronghold-Protocol/issues/405","comments":[{"body":"0.2.2 修复"}]}'
            self.assertEqual(args[0:2], ["search","issues"])
            self.assertNotIn("--shell", args)
            if args[2] == "叠不了层":
                return '[{"title":"叠不了层","url":"https://github.com/sganggs/Stronghold-Protocol/issues/405","state":"open","body":"test"}]'
            return '[]'
        with patch.object(m,"gh",fake_gh) as mock_gh:
            out = m.search_issues({"query":"打铁 bug 修好了吗"})
        self.assertIn("/issues/405",out)
    def test_public_content_blocks_redirect(self):
        with self.assertRaises(ValueError):
            m._SafeRedirect().redirect_request(None,None,302,"redirect",{},"http://127.0.0.1/")
    def test_search_does_not_execute_shell(self):
        import subprocess
        fake = type("Result",(),{"returncode":0,"stdout":"[]","stderr":""})()
        with patch.object(subprocess,"run",return_value=fake) as run:
            m.gh(["search","issues","叠层","--repo",m.REPOS[0]])
        self.assertEqual(run.call_args.args[0][0],"gh")
        self.assertFalse(run.call_args.kwargs["check"])
        self.assertNotIn("shell",run.call_args.kwargs)

if __name__=="__main__":
    main()
