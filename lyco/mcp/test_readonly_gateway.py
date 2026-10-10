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
        self.assertEqual(len(m.TOOLS), 8)
        self.assertNotIn("bash", [x["name"] for x in m.TOOLS])
        for name in ("write", "exec", "github_issue_create", "file_edit"):
            with self.assertRaises(ValueError):
                m.dispatch(name, {})
    def test_prts_search_safe_and_sourced(self):
        with patch.object(m, "_prts_api", return_value=["凯尔希", ["凯尔希"], [""], ["https://prts.wiki/w/凯尔希"]]) as api:
            parsed = __import__("json").loads(m.prts_search({"query":"凯尔希"}))
        self.assertEqual(parsed["results"][0]["title"],"凯尔希")
        self.assertEqual(api.call_args.args[0]["action"],"opensearch")
        with self.assertRaises(ValueError):
            m.prts_search({"query":"x"+chr(10)+"bad"})
        with self.assertRaises(ValueError):
            m.prts_page({"title":""})

    def test_prts_page_reads_wikitext_fields(self):
        def fake_api(params):
            if params.get("prop") == "extracts":
                return {"query":{"pages":{"42":{"title":"凯尔希","extract":"干员信息"}}}}
            return {"query":{"pages":{"42":{"revisions":[{"slots":{"main":{"*":"|干员名=凯尔希\n|职业=医疗\n|干员id=char_003_kalts\n"}}}]}}}}
        with patch.object(m,"_prts_api",side_effect=fake_api):
            d=__import__("json").loads(m.prts_page({"title":"凯尔希"}))
        self.assertEqual(d["fields"]["职业"],"医疗")
        self.assertEqual(d["url"],"https://prts.wiki/w/"+m.urllib.parse.quote(d["title"],safe="():"))

    def test_stronghold_mechanic_is_read_from_fixed_prts_section(self):
        section = ("=== 附加盟约 ===\\n"
                   "{{/盟约|盟约=不屈|人数=2|效果=地面干员退场时，"
                   "有{{color|#0098DC|(18+0.4×层数)%}}概率立即重新部署"
                   "<br>再部署时间和费用归零|干员=...}}")
        with patch.object(m, "_stronghold_section",
                          side_effect=lambda title, sec: section if sec == "3" else "") as lookup, patch.object(m, "fetch_public",
                              return_value="区是蛆的谐音，在本群表示垃圾/很弱"):
            d = __import__("json").loads(m.stronghold_wiki_lookup(
                {"query": "为什么大家说不屈是区"}))
        self.assertEqual(d["keyword"], "不屈")
        self.assertEqual(d["required_operators"], 2)
        self.assertIn("18+0.4×层数", d["mechanic"])
        self.assertIn("prts.wiki/w/", d["source_url"])
        self.assertIn("not player slang", d["evidence_limit"])
        self.assertIn("蛆", d["community_usage"]["definition"])
        self.assertTrue(d["community_usage"]["not_a_mechanic"])
        self.assertEqual(d["community_usage"]["source_type"],"community-provided slang")
        self.assertIn("/stronghold-knowledge/blob/main/terms/", d["community_usage"]["source_url"])
        self.assertNotIn("废都区", d["mechanic"])
        self.assertEqual(lookup.call_args_list[0].args[1], "2")

    def test_stronghold_zone_not_confused_with_slang(self):
        with patch.object(m,"fetch_public") as public:
            self.assertIsNone(m._stronghold_community_note("部署区有什么用"))
            public.assert_not_called()

    def test_stronghold_general_flow_uses_prts_simulation_guide(self):
        with patch.object(m, "_stronghold_section",
                          side_effect=lambda title, sec: "== 模拟流程 ==\\n* 准备干员\\n* 打败最终领袖" if sec == "6" else ""):
            d = __import__("json").loads(m.stronghold_wiki_lookup(
                {"query": "卫戍协议怎么玩"}))
        self.assertEqual(d["topic"], "卫戍协议玩法")
        self.assertIn("打败最终领袖", d["guide_excerpt"])
        self.assertIn("prts.wiki", d["source_url"])

    def test_stronghold_lookup_rejects_control_chars(self):
        with self.assertRaises(ValueError):
            m.stronghold_wiki_lookup({"query": "不屈" + chr(10) + "bad"})

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
