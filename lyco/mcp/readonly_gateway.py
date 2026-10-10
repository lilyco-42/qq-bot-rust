#!/usr/bin/env python3
"""Read-only MCP gateway for the public QQ bot's ZeroStack process.

Use only explicitly enumerated public resources. Never expose bash, file writes,
Github issue mutations, authenticated project secrets or arbitrary MCP servers.
All input is untrusted tool arguments; commands use argv, never shell=True.
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from html.parser import HTMLParser

REPOS = ("sganggs/Stronghold-Protocol", "lilyco-42/Stronghold-Protocol",
         "lilyco-42/StrongholdProtocolClient")
PUBLIC_HOSTS = frozenset(("github.com", "raw.githubusercontent.com", "prts.wiki",
                          "sp.lain42.top", "lain42.top"))
MAX_OUTPUT = 2600
TOOLS = [
    {"name": "github_search_issues",
     "description": "Search public GitHub issues and PRs in upstream sganggs/Stronghold-Protocol, the lilyco-42 fork and StrongholdProtocolClient. Always search before answering recent bug/fixed/release questions. Summarize with actual issue links and status; no match does not prove bug fixed. Chinese 打铁 may also mean 铁钳号 / 白铁 / 圣约送葬人 / 叠层.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string", "description": "Issue search words; not a shell command."},
         "limit": {"type": "integer", "minimum": 1, "maximum": 15}},
         "required": ["query"], "additionalProperties": False}},
    {"name": "github_issue_detail",
     "description": "Read one issue and up to 5 comments in the selected fixed upstream/fork/client repository; use for evidence about bug status and version of fix.",
     "inputSchema": {"type": "object", "properties": {
         "repo": {"type": "string", "enum": list(REPOS)},
         "number": {"type": "integer", "minimum": 1}},
         "required": ["repo", "number"], "additionalProperties": False}},
    {"name": "github_client_release",
     "description": "Find the latest public client GitHub Release and its real assets; do not mistake payload-only Release for installable APK.",
     "inputSchema": {"type": "object", "properties": {},
         "additionalProperties": False}},
    {"name": "game_status",
     "description": "Read only public sp.lain42.top game /healthz status; do not log in or use credentials.",
     "inputSchema": {"type": "object", "properties": {},
         "additionalProperties": False}},
    {"name": "public_page",
     "description": "Read a public page from allowlisted GitHub, PRTS Wiki or sp.lain42.top; no LAN/private sites, credentials, commands or mutations.",
     "inputSchema": {"type": "object", "properties": {
         "url": {"type": "string", "maxLength": 400}},
         "required": ["url"], "additionalProperties": False}},
]

def gh(args, timeout=12):
    p = subprocess.run(["gh", *args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, encoding="utf-8",
                       errors="replace", timeout=timeout, check=False)
    if p.returncode:
        error = p.stderr.strip().splitlines()
        raise RuntimeError((error[0] if error else "GitHub CLI failed")[:260])
    return p.stdout[:30000]

def clip(s, max_chars=MAX_OUTPUT):
    return s[:max_chars] + ("…[truncated]" if len(s) > max_chars else "")

def search_issues(args):
    query = str(args.get("query", "")).strip()[:120]
    if not query or "\x00" in query:
        raise ValueError("Non-empty issue search query required")
    limit = min(8, max(1, int(args.get("limit", 5))))
    terms = [query]
    nickname = any(word in query for word in ("打铁", "铁钳", "送葬", "白铁"))
    # Indexes may not search issue comments; the nicknames often only appear
    # in comments on the upstream "叠不了层" report.
    if nickname:
        terms += ["叠不了层", "圣约送葬人"]
    results = []
    seen = set()
    for term in terms[:3]:
        raw = gh(["search", "issues", term,
                  *[part for repo in REPOS for part in ("--repo", repo)],
                  "--limit", str(limit),
                  "--json", "number,title,state,url,updatedAt,body"], timeout=15)
        for item in json.loads(raw):
            url = item.get("url")
            if url in seen:
                continue
            seen.add(url)
            results.append({
                "url": url, "title": item.get("title"),
                "state": item.get("state"), "updatedAt": item.get("updatedAt"),
                "bodyExcerpt": (item.get("body") or "")[:125]})
    if nickname:
        results.sort(key=lambda item: 0 if item.get("url", "").endswith("/issues/405") else 1)
        # Surface the maintainer's version statement, not just a bare issue title.
        if results and results[0].get("url", "").endswith("/issues/405"):
            try:
                detail = json.loads(issue_detail({"repo": REPOS[0], "number": 405}))
                recent = detail.get("comments", [])
                if recent:
                    results[0]["maintainerNote"] = recent[-1]["body"][:750]
                    results[0]["noteUrl"] = recent[-1].get("url")
            except (RuntimeError, ValueError, subprocess.TimeoutExpired):
                pass
    return json.dumps(results[:6], ensure_ascii=False) if results else "No issue matches were found in the searched repositories; this does NOT establish a fix."

def issue_detail(args):
    repo = args.get("repo")
    number = args.get("number")
    if repo not in REPOS or type(number) is not int or not 0 < number < 10000000:
        raise ValueError("Invalid fixed repo or issue number")
    raw = gh(["issue", "view", str(number), "--repo", repo,
              "--json", "number,title,body,state,url,comments"], timeout=12)
    x = json.loads(raw)
    return json.dumps({
        "title": x.get("title"), "state": x.get("state"),
        "url": x.get("url"), "body": (x.get("body") or "")[:3000],
        "comments": [{"body": (i.get("body") or "")[:900],
                      "url": i.get("url")} for i in x.get("comments", [])[-5:]]
    }, ensure_ascii=False)

def client_release(_args):
    x = json.loads(gh(["release", "view", "--repo",
                       "lilyco-42/StrongholdProtocolClient",
                       "--json", "tagName,publishedAt,url,assets"]))
    return json.dumps({
        "tag": x.get("tagName"), "publishedAt": x.get("publishedAt"),
        "url": x.get("url"),
        "payloadOnly": str(x.get("tagName", "")).startswith("payload-"),
        "assets": [{"name": a.get("name"), "size": a.get("size")}
                   for a in (x.get("assets") or [])[:25]]
    }, ensure_ascii=False)

class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def check_url(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or p.hostname not in PUBLIC_HOSTS or p.username or p.password or p.port not in (None, 443):
        raise ValueError("Only allowlisted public HTTPS pages are permitted")
    return url

class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.skip += 1
    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self.skip = max(0, self.skip-1)
    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)

def fetch_public(url):
    check_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "LycoBot-ReadOnly/1.0", "Accept": "text/html,application/json,text/plain"})
    opener = urllib.request.build_opener(_SafeRedirect())
    with opener.open(request, timeout=8) as r:
        content_type = r.headers.get("Content-Type", "")
        if not any(t in content_type for t in ("text/", "json", "xml")):
            raise ValueError("Page is not a text resource")
        raw = r.read(32000).decode("utf-8", errors="replace")
    if "html" in content_type:
        p = _PageParser()
        p.feed(raw)
        raw = " ".join(p.parts)
    return clip(re.sub(r"\s+", " ", unescape(raw)), 3600)

def dispatch(name, args):
    if not isinstance(args, dict):
        raise ValueError("Tool arguments must be an object")
    if name == "github_search_issues":
        return search_issues(args)
    if name == "github_issue_detail":
        return issue_detail(args)
    if name == "github_client_release":
        return client_release(args)
    if name == "game_status":
        return fetch_public("https://sp.lain42.top/healthz")
    if name == "public_page":
        return fetch_public(str(args.get("url", "")))
    raise ValueError("Unknown tool")

def respond(id_, result=None, error=None):
    obj = {"jsonrpc": "2.0", "id": id_}
    obj["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def handle(msg):
    method = msg.get("method")
    id_ = msg.get("id")
    if method == "initialize":
        respond(id_, {"protocolVersion": "2024-11-05",
                     "capabilities": {"tools": {}},
                     "serverInfo": {"name": "lyco-readonly", "version": "1.0.0"}})
    elif method in ("notifications/initialized", "notifications/cancelled"):
        return
    elif method == "ping":
        respond(id_, {})
    elif method == "tools/list":
        respond(id_, {"tools": TOOLS})
    elif method == "tools/call":
        p = msg.get("params") or {}
        try:
            text = dispatch(p.get("name"), p.get("arguments") or {})
            respond(id_, {"content": [{"type": "text", "text": clip(text)}], "isError": False})
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired, urllib.error.URLError) as exc:
            respond(id_, {"content": [{"type": "text", "text": clip(str(exc), 260)}], "isError": True})
    elif id_ is not None:
        respond(id_, error={"code": -32601, "message": "Method not found"})

def main():
    # MCP stdio is newline-delimited JSON-RPC. Never log secrets or emit logs on stdout.
    for raw in sys.stdin:
        if len(raw) > 12000:
            continue
        try:
            item = json.loads(raw)
            if isinstance(item, dict):
                handle(item)
        except Exception as exc:
            print(f"mcp input ignored: {type(exc).__name__}", file=sys.stderr)

if __name__ == "__main__":
    main()
