#!/usr/bin/env bash
# QQ bot 自更新：拉最新版本 → 校验 → 原子替换 → 重启 → 健康检查 → 失败回滚。
#
# 为什么写得这么啰嗦（每一条都对应一个真实的翻车方式）：
#   1. **失败必须回滚**：宁可留着旧版本继续跑，也不能让 bot 停在坏版本上；
#   2. **校验不过就不装**（fail closed）：拿不到 sha256 或对不上，直接放弃更新，
#      避免中间人替换 / 半截下载被当成新版本；
#   3. **装前先试着执行**：新二进制先跑一次 `--version`（不读任何密钥），
#      架构不对、被截断、缺可执行位都能在替换之前发现；
#   4. **幂等**：版本没变就什么都不做 —— 每 10 分钟跑一次，绝大多数次是 no-op；
#   5. **单实例**：flock 兜住「定时器触发」与「人手执行」的并发；
#   6. **不碰 env.sh**：更新只换二进制，凭证与配置永远由人掌握。
#
# 用法：
#   update.sh            # 检查并按需更新（幂等）
#   update.sh --check    # 只看远端版本与本地是否一致，不动任何文件
#   UPDATE_SOURCE=static UPDATE_BASE_URL=https://example.com/qqbot update.sh
#   RESTART_CMD='supervisorctl restart qqbot' update.sh   # 非 systemd 的进程管理器
set -euo pipefail

APP_DIR="${APP_DIR:-/home/radxa/qq_bot}"
SERVICE="${SERVICE:-qqbot}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/healthz}"
LOG_FILE="${LOG_FILE:-${APP_DIR}/update.log}"
STATE_DIR="${STATE_DIR:-${APP_DIR}/.update}"
LOCK_FILE="${LOCK_FILE:-/tmp/qqbot-update.lock}"
VERSION_FILE="${VERSION_FILE:-${APP_DIR}/VERSION}"
BIN_NAME="webhook_server"

# 更新源：
#   github —— 走 GitHub Releases（私有库也可，靠 GH_TOKEN）
#   static —— 走静态目录：$UPDATE_BASE_URL/{latest.txt,$BIN_NAME,$BIN_NAME.sha256}
UPDATE_SOURCE="${UPDATE_SOURCE:-github}"
UPDATE_REPO="${UPDATE_REPO:-lilyco-42/qq-bot-rust}"
UPDATE_BASE_URL="${UPDATE_BASE_URL:-}"
UPDATE_TIMEOUT="${UPDATE_TIMEOUT:-60}"
HEALTH_RETRIES="${HEALTH_RETRIES:-30}"
KEEP_BACKUPS="${KEEP_BACKUPS:-3}"

CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

# ── 日志 ────────────────────────────────────────────────────────────────
log() {
  local line
  line="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$line"
  # 简单轮转：超过 256KB 就只留最后 200 行，避免日志无限长大。
  if [ -f "$LOG_FILE" ] && [ "$(wc -c <"$LOG_FILE")" -gt 262144 ]; then
    tail -n 200 "$LOG_FILE" >"${LOG_FILE}.tmp" && mv -f "${LOG_FILE}.tmp" "$LOG_FILE"
  fi
  echo "$line" >>"$LOG_FILE" 2>/dev/null || true
}
die() {
  log "ERROR $*"
  exit 1
}

# ── 载入配置（env.sh 里已经有 GH_TOKEN，更新脚本需要它拉私有库资产） ──
if [ -f "${APP_DIR}/env.sh" ]; then
  # shellcheck disable=SC1090
  set -a
  . "${APP_DIR}/env.sh"
  set +a
fi
# update.env 可覆盖上面所有 UPDATE_* / HEALTH_URL 等设置（可选文件）。
if [ -f "${APP_DIR}/update.env" ]; then
  # shellcheck disable=SC1090
  set -a
  . "${APP_DIR}/update.env"
  set +a
fi

# ── 单实例 ──────────────────────────────────────────────────────────────
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  log "另一次更新仍在进行，跳过本轮"
  exit 0
fi

mkdir -p "$STATE_DIR"

# ── 本地版本 ────────────────────────────────────────────────────────────
current_version() {
  if [ -s "$VERSION_FILE" ]; then
    # 单进程 awk：不要用 `head -n 1 |` —— 见文件末尾「pipefail 陷阱」。
    awk 'NR==1{gsub(/[[:space:]]/,"");print}' "$VERSION_FILE"
    return
  fi
  # 没有 VERSION 文件（首次接管的老部署）：问二进制自己；问不到就当作未知。
  if [ -x "${APP_DIR}/${BIN_NAME}" ]; then
    "${APP_DIR}/${BIN_NAME}" --version 2>/dev/null | awk 'NR==1{print $2}'
  fi
}

# ── 远端版本 ────────────────────────────────────────────────────────────
remote_version() {
  case "$UPDATE_SOURCE" in
  github)
    if command -v gh >/dev/null 2>&1; then
      gh release view --repo "$UPDATE_REPO" --json tagName --jq .tagName 2>/dev/null
    else
      # 没有 gh 就用 API（私有库要 token；公开库不需要）。
      local auth=()
      [ -n "${GH_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GH_TOKEN}")
      curl -fsS --max-time "$UPDATE_TIMEOUT" "${auth[@]}" \
        -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${UPDATE_REPO}/releases/latest" |
        awk 'match($0,/"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"/){v=substr($0,RSTART,RLENGTH);sub(/.*"/,"",v);sub(/"$/,"",v);print v;exit}'
    fi
    ;;
  static)
    [ -n "$UPDATE_BASE_URL" ] || die "static 模式必须设置 UPDATE_BASE_URL"
    # 端点只输出一行；用 awk 一次性取首行，避免 `head -n 1` 提前关闭管道。
    curl -fsS --max-time "$UPDATE_TIMEOUT" "${UPDATE_BASE_URL}/latest.txt" |
      awk 'NR==1{print;exit}'
    ;;
  *)
    die "未知 UPDATE_SOURCE=${UPDATE_SOURCE}（可选 github / static）"
    ;;
  esac
}

# ── 下载资产到 $1 目录 ──────────────────────────────────────────────────
download_assets() {
  local dest="$1" version="$2"
  case "$UPDATE_SOURCE" in
  github)
    if command -v gh >/dev/null 2>&1; then
      # --pattern 可重复；--clobber 允许覆盖上一轮残留。
      gh release download "$version" --repo "$UPDATE_REPO" \
        --pattern "$BIN_NAME" --pattern "$BIN_NAME.sha256" \
        --dir "$dest" --clobber >/dev/null || return 1
    else
      local auth=()
      [ -n "${GH_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GH_TOKEN}")
      local base="https://github.com/${UPDATE_REPO}/releases/download/${version}"
      curl -fsSL --max-time "$UPDATE_TIMEOUT" "${auth[@]}" -o "${dest}/${BIN_NAME}" "${base}/${BIN_NAME}" || return 1
      curl -fsSL --max-time "$UPDATE_TIMEOUT" "${auth[@]}" -o "${dest}/${BIN_NAME}.sha256" "${base}/${BIN_NAME}.sha256" || return 1
    fi
    ;;
  static)
    curl -fsSL --max-time "$UPDATE_TIMEOUT" -o "${dest}/${BIN_NAME}" "${UPDATE_BASE_URL}/${BIN_NAME}" || return 1
    curl -fsSL --max-time "$UPDATE_TIMEOUT" -o "${dest}/${BIN_NAME}.sha256" "${UPDATE_BASE_URL}/${BIN_NAME}.sha256" || return 1
    ;;
  esac
  [ -s "${dest}/${BIN_NAME}" ] || return 1
  return 0
}

# ── 健康检查：必须「新版本真的在服务」才算成功 ──────────────────────────
wait_healthy() {
  local want="$1" i body
  for i in $(seq 1 "$HEALTH_RETRIES"); do
    if body=$(curl -fsS --max-time 3 "$HEALTH_URL" 2>/dev/null); then
      case "$body" in
      *"version=${want}"*) return 0 ;;
      esac
    fi
    sleep 1
  done
  return 1
}

# ── 回滚到最近一次备份 ──────────────────────────────────────────────────
rollback() {
  local prev_bin prev_ver
  prev_bin=$(ls -1t "${STATE_DIR}"/prev-*."${BIN_NAME}" 2>/dev/null | head -n 1 || true)
  if [ -z "$prev_bin" ]; then
    log "ERROR 没有可用备份，无法回滚（请人工检查 ${APP_DIR}）"
    return 1
  fi
  prev_ver=$(cat "${prev_bin}.version" 2>/dev/null || echo "")
  install -m 0755 "$prev_bin" "${APP_DIR}/${BIN_NAME}"
  [ -n "$prev_ver" ] && printf '%s\n' "$prev_ver" >"$VERSION_FILE"
  restart_service || true
  if wait_healthy "$prev_ver"; then
    log "已回滚到 ${prev_ver:-上一个版本}，服务正常"
  else
    log "ERROR 回滚后健康检查仍未通过 —— 需要人工介入"
  fi
}

# ── 能否重启服务 ────────────────────────────────────────────────────────
#
# ⚠️ 这里**故意不用** `systemctl list-unit-files | grep -q ...`：
# grep -q 一命中就退出，systemctl 收到 SIGPIPE 以 141 结束；本脚本开了
# `set -o pipefail`，于是整条管道被判失败 —— 结果是「明明装了单元却报未发现」，
# 更新会静默跳过重启（2026-10-10 实机踩到）。改用无需管道的取值比较。
unit_loaded() {
  command -v systemctl >/dev/null 2>&1 || return 1
  [ "$(systemctl show -p LoadState --value "$SERVICE" 2>/dev/null)" = "loaded" ]
}

# 重启能力探测：RESTART_CMD 是留给其它进程管理器（supervisor/自研守护）的逃生口。
can_restart() {
  [ -n "${RESTART_CMD:-}" ] && return 0
  unit_loaded
}

restart_service() {
  if [ -n "${RESTART_CMD:-}" ]; then
    sh -c "$RESTART_CMD" || die "RESTART_CMD 执行失败：${RESTART_CMD}"
    return 0
  fi
  if ! unit_loaded; then
    die "无法重启：systemd 里没有 ${SERVICE}.service（可用 RESTART_CMD 指定其它方式）"
  fi
  if [ "$(id -u)" = "0" ]; then
    systemctl restart "$SERVICE"
  else
    sudo -n systemctl restart "$SERVICE" ||
      die "重启失败：请确认已装 ${SERVICE}.service 与 sudo 免密规则（deploy/install.sh）"
  fi
}

# ── 主流程 ──────────────────────────────────────────────────────────────
CUR=$(current_version || true)
LATEST=$(remote_version | tr -d '[:space:]' || true)

if [ -z "$LATEST" ]; then
  log "拿不到远端版本（源=${UPDATE_SOURCE}）—— 保持现状，下轮再试"
  exit 0
fi

if [ "$CHECK_ONLY" = "1" ]; then
  log "本地=${CUR:-未知} 远端=${LATEST}（仅检查，未改动）"
  [ "$CUR" = "$LATEST" ] && exit 0 || exit 10
fi

if [ "$CUR" = "$LATEST" ]; then
  log "已是最新（${LATEST}），无需更新"
  exit 0
fi

log "发现新版本 ${CUR:-未知} → ${LATEST}，开始更新"

# 前置闸门：换二进制的前提是「有人能把它跑起来」。
# 不能重启就别动文件 —— 否则文件换了、跑着的还是旧代码，接着被健康检查判失败再回滚，
# 白折腾一轮还留下一堆备份。
if ! can_restart; then
  log "WARN 有新版但无法重启服务（未装 ${SERVICE}.service，且未设 RESTART_CMD）—— 保持现状，不动二进制"
  exit 0
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if ! download_assets "$TMP_DIR" "$LATEST"; then
  log "ERROR 下载失败（版本 ${LATEST}）—— 保持现状，下轮再试"
  exit 0
fi

# 校验一：sha256 必须存在且一致（fail closed）。
if [ ! -s "${TMP_DIR}/${BIN_NAME}.sha256" ]; then
  die "缺少 ${BIN_NAME}.sha256，拒绝安装未校验的二进制"
fi
EXPECTED=$(awk '{print $1}' "${TMP_DIR}/${BIN_NAME}.sha256" | head -n 1 | tr -d '[:space:]')
ACTUAL=$(sha256sum "${TMP_DIR}/${BIN_NAME}" | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  die "sha256 不匹配（期望 ${EXPECTED}，实际 ${ACTUAL}）—— 拒绝安装"
fi

# 校验二：新二进制自己能跑起来（架构/截断/权限问题在这里暴露，而不是替换之后）。
chmod 0755 "${TMP_DIR}/${BIN_NAME}"
if ! "${TMP_DIR}/${BIN_NAME}" --version >/dev/null 2>&1; then
  die "新二进制无法执行（架构不符或文件损坏），已放弃更新"
fi

# 备份现状 → 原子替换（同目录 mv，不存在「半个文件」窗口）。
TS=$(date '+%Y%m%d%H%M%S')
if [ -x "${APP_DIR}/${BIN_NAME}" ]; then
  cp -p "${APP_DIR}/${BIN_NAME}" "${STATE_DIR}/prev-${TS}.${BIN_NAME}"
  printf '%s\n' "$CUR" >"${STATE_DIR}/prev-${TS}.${BIN_NAME}.version"
fi
install -m 0755 "${TMP_DIR}/${BIN_NAME}" "${APP_DIR}/${BIN_NAME}.new"
mv -f "${APP_DIR}/${BIN_NAME}.new" "${APP_DIR}/${BIN_NAME}"
printf '%s\n' "$LATEST" >"$VERSION_FILE"
log "二进制已替换，准备重启 ${SERVICE}"

if ! restart_service; then
  rollback
  exit 1
fi

if wait_healthy "$LATEST"; then
  log "更新成功：${CUR:-未知} → ${LATEST}"
else
  log "ERROR 新版本健康检查未通过（${LATEST}），开始回滚"
  rollback
  exit 1
fi

# 清理旧备份，只留最近 KEEP_BACKUPS 份。
ls -1t "${STATE_DIR}"/prev-*."${BIN_NAME}" 2>/dev/null |
  tail -n "+$((KEEP_BACKUPS + 1))" |
  while read -r old; do
    rm -f "$old" "${old}.version"
  done

exit 0

# ─────────────────────────────────────────────────────────────────────────
# pipefail 陷阱（2026-10-10 实机踩到，值得单独记一笔）
#
# 本脚本开了 `set -euo pipefail`。凡是用「提前退出的读取器」收尾的管道，
# 上游会收到 SIGPIPE（退出码 141），pipefail 就把它当成整条管道失败：
#
#   ❌ systemctl list-unit-files | grep -q "^qqbot.service"   # 命中即 SIGPIPE → 141
#   ❌ curl ... | head -n 1                                   # 同理
#   ✅ systemctl show -p LoadState --value qqbot              # 不用管道
#   ✅ ... | awk 'NR==1{print;exit}'                          # awk 一次性读完
#
# 症状特别阴：交互 shell 里手敲同样的命令一切正常，只有在 `set -o pipefail`
# 的脚本里才失败，于是「明明装了 systemd 单元却报未发现，静默跳过重启」。
# 改这个文件时请守住上面两条 ✅ 的写法。
# ─────────────────────────────────────────────────────────────────────────
