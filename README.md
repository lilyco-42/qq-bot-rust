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
