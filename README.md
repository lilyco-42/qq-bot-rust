# QQ Bot Rust

Radxa ARM64 QQ bot, webhook gateway and public GitHub Actions releases.


## QQ group images and OCR

The optional vision feature handles image attachments in QQ group and C2C
messages, and is enabled in production release builds. The input pipeline
validates the HTTPS QQ CDN hostname, disallows redirects, enforces 5 MiB and
14 MP bounds, checks format magic, and converts PNG/JPEG/WebP/GIF to JPEG.
A Base64 JPEG data URI is submitted to a multimodal model which performs both
image understanding and OCR (recognition of readable text in the image).

The public repository lilyco-42/lilyco currently contains lilyco-vision for
image manipulation, but no OCR module at the referenced path. This bot supplies
its own model-based OCR adapter; no separate Tesseract binary is required on Radxa.
Screenshots, Base64 payload and API credentials are not written to group memory.

Set on the server (never commit real tokens):
- VISION_API_KEY: optional, falls back to NIM_API_KEY
- VISION_API_URL: optional, defaults to https://integrate.api.nvidia.com/v1/chat/completions
- VISION_MODEL: optional, defaults to meta/llama-3.2-11b-vision-instruct

Image processing failure yields an explicit diagnostic, not a fabricated OCR
result. Images are transmitted to an external AI provider; avoid private
screenshots unless this transfer is acceptable. Screenshot text is untrusted
and never executed as instructions.


## Persistent QQ group knowledge

The /记 command or a direct message beginning with 记住 writes an important
fact to the current group's Turso database. The /忆 command only reads
and reinforces stored knowledge and never writes the message as a new fact.
On subsequent questions such as 0.2.3版本更新了什么, the bot first searches
saved version facts in the same group before calling the stateless AI model.
The answer is labelled as group-provided and not independently verified.
Generated AI answers never become authoritative facts.

An administrator can import one fact at the next process startup by writing
a UTF-8 file named .memory-import in the bot working directory. The first
line is the QQ group's hexadecimal openid; all remaining lines contain the
fact. On successful Turso write, the bot removes the import file. Do NOT
commit group IDs or import files to this public repository. Alternatively
set MEMORY_IMPORT_FILE to a file path controlled by the administrator.


## Stronghold Protocol game room directory

The new `/游戏房间` (aliases: `/卫戍房间`, `/sp房间`, `/gamerooms`) reads the actual Stronghold game waiting rooms; it is separate from `/房间`, which reads the online-platform lobby. The command is read-only and never joins a game.

On Radxa, configure `SP_ROOM_API_URL=https://sp.lain42.top/api/bot/v1/rooms?limit=10` and `SP_ROOM_API_TOKEN` in the bot's private service environment. The Bearer token must not be committed, logged, sent to a chat, or injected into an LLM prompt. Missing configuration or a service outage returns an explicit message rather than invented rooms.

The server adapter and protocol are in [lain42-stronghold-ops](https://github.com/lilyco-42/lain42-stronghold-ops/tree/main/extensions/sp-room-api). It requires authentication and only returns waiting-room codes, safe player display names, seat counts, difficulty and the optional AI-draft-order strategy. In-match selections and player credentials remain private. This adapter is opt-in at the Stronghold systemd layer and needs a planned game service restart before the endpoint becomes live.

## Quark Drive share transfer via QQ Bot

`/夸克转存 https://pan.quark.cn/s/abc123` (alias `/网盘转存`) uses the third-party [QuarkPan CLI](https://github.com/lich0821/QuarkPan) to copy a Quark share into the operator's own Quark Drive.

**Security by default:** transfer is a write operation and remains **disabled** unless `QUARK_SAVE_ENABLED=1` and the sender's exact QQ user OpenID is included in `QUARK_SAVE_ALLOWED_OPENIDS`. Do not use the QQ group OpenID for this allowlist. No group user can supply an executable name, destination directory or shell arguments. No command shell is used; at most one task runs at once with a 105 second watchdog. The CLI subprocess receives only a small whitelist of environment variables, not QQ or AI credentials. The reply contains no file contents, login cookies or API tokens.

On the always-on **QQ Bot device** (Radxa), install QuarkPan (e.g. into a dedicated virtual environment) and log in using that **same Linux service account** with `quarkpan auth login`. Set these in the bot's private systemd environment, not in Git:

- `QUARK_SAVE_ENABLED=1` (default: disabled)
- `QUARK_SAVE_ALLOWED_OPENIDS=<QQ user OpenID>[,other OpenID]`
- `QUARKPAN_BIN=/path/to/quarkpan` (default: `quarkpan`)
- `QUARK_SAVE_FOLDER=/来自QQ群/` (default, not user-selectable)

If the CLI returns success, the bot reports this outcome but asks you to verify the file in your drive. Login expiry, revoked links and capacity failures return a clear error. This code does **not** install QuarkPan, ask for a cookie in a QQ group, start any automatic scheduled task, or transfer any files until you configure the service and an administrator explicitly submits a share link. The bot works even when Windows is powered off.

Only transfer content you are authorized to access and store. The tool is unofficial and its dependencies and Quark session credentials should be reviewed and kept isolated from other server services.
