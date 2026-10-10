# Lyco ZeroStack read-only MCP

This gateway connects ZeroStack to scoped, bounded, read-only public resources:
- github_search_issues: upstream sganggs/Stronghold-Protocol, lilyco-42 fork, and client.
- github_issue_detail: issue description, state and recent comments.
- github_client_release: latest release and actual asset names.
- game_status: public game health status.
- public_page: text-only allowlisted HTTPS pages.

Rust still handles identity, scoped group memory, administrator commands,
issue creation, QQ images and bot delivery. The public bot cannot use arbitrary
bash, read/write filesystem, GitHub mutations, credentials or LAN requests.

Deployment on Radxa:
1. Copy readonly_gateway.py to /home/radxa/qq_bot/readonly_gateway.py.
2. Set owner radxa, permissions 0644; verify Python 3 and gh are installed.
3. Copy the user's ZeroStack config to
   /home/radxa/qq_bot/zs-readonly/zerostack/config.toml, change no_tools
   to false. Config file permissions 0600, directory 0700.
4. Add QA_READONLY_MCP=1 to the protected qqbot env.sh and deploy the Rust
   bot. Keep normal chat without MCP until after tests pass.

Security caveat: ZeroStack 1.8.4 treats every MCP call as privileged even in
readonly mode. This bot invokes ZeroStack with dangerously-skip-permissions
ONLY alongside an exact tools allowlist of the five names above. The gateway
itself implements no writes, no arbitrary commands and rejects private URLs.
The subprocess receives an isolated XDG_CONFIG_HOME, no external hooks,
context files or persistent sessions. Never expose bash/edit/write with these
permission settings; do not extend the allowlist without code review.

For a rollback, change QA_READONLY_MCP=0 and restart qqbot; slash commands
still work. The existing user-wide ZeroStack config is left unchanged.

Tests:
    python3 -m unittest discover -s lyco/mcp -p test_*.py

A successful functional probe must show a real tool call rather than a
text-only request pretending to call GitHub.
