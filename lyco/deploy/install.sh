#!/usr/bin/env bash
# 一次性安装（在 Radxa 上以 root 权限执行）：把常驻服务与自更新定时器装到位。
#
#   sudo bash deploy/install.sh
#
# 装完之后的常态是：**再也不用 SSH 上来维护**。
#   - qqbot.service       常驻，崩了自动拉起
#   - qqbot-update.timer  每 10 分钟检查一次新版本，自己下载/校验/切换/回滚
# 你要做的只有一件事：本地改完代码，打个 tag 推上去。
set -euo pipefail

APP_DIR="${APP_DIR:-/home/radxa/qq_bot}"
RUN_USER="${RUN_USER:-radxa}"
SERVICE="${SERVICE:-qqbot}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

if [ "$(id -u)" != "0" ]; then
  echo "请用 root 运行：sudo bash $0" >&2
  exit 1
fi

say "检查部署目录 $APP_DIR"
[ -d "$APP_DIR" ] || { echo "缺少 $APP_DIR" >&2; exit 1; }
if [ ! -f "${APP_DIR}/env.sh" ]; then
  echo "警告：${APP_DIR}/env.sh 不存在 —— 服务会因为缺少凭证起不来" >&2
fi

say "安装更新脚本"
install -o "$RUN_USER" -g "$RUN_USER" -m 0755 "${SCRIPT_DIR}/update.sh" "${APP_DIR}/update.sh"
mkdir -p "${APP_DIR}/.update"
chown "$RUN_USER:$RUN_USER" "${APP_DIR}/.update"

# 首次接管的老部署没有 VERSION 文件：直接问二进制，之后更新脚本就能比对版本了。
if [ ! -s "${APP_DIR}/VERSION" ] && [ -x "${APP_DIR}/webhook_server" ]; then
  VER=$("${APP_DIR}/webhook_server" --version 2>/dev/null | head -n 1 | awk '{print $2}' || true)
  if [ -n "${VER:-}" ]; then
    printf '%s\n' "$VER" >"${APP_DIR}/VERSION"
    say "记录当前版本：$VER"
  else
    say "警告：取不到当前版本（旧二进制不支持 --version）—— 首次更新会整包替换"
  fi
fi

say "安装 systemd 单元"
for unit in qqbot.service qqbot-update.service qqbot-update.timer; do
  install -m 0644 "${SCRIPT_DIR}/${unit}" "/etc/systemd/system/${unit}"
done

# 更新脚本要以普通用户身份重启服务 → 只放行这两条 systemctl 命令，别的一概不给。
SYSTEMCTL="$(command -v systemctl)"
say "写入 sudo 免密规则（仅 $SYSTEMCTL restart/start/is-active $SERVICE）"
cat >/etc/sudoers.d/qqbot-update <<EOF
# 由 deploy/install.sh 生成：允许 ${RUN_USER} 免密重启机器人服务（最小权限）。
${RUN_USER} ALL=(root) NOPASSWD: ${SYSTEMCTL} restart ${SERVICE}, ${SYSTEMCTL} start ${SERVICE}, ${SYSTEMCTL} is-active ${SERVICE}
EOF
chmod 0440 /etc/sudoers.d/qqbot-update
visudo -cf /etc/sudoers.d/qqbot-update

# 旧部署可能还是 nohup 手工跑的：先收掉，免得两个进程抢同一个 webhook 端口。
if pgrep -x webhook_server >/dev/null 2>&1; then
  say "停掉手工启动的 webhook_server（交给 systemd 接管）"
  pkill -x webhook_server || true
  sleep 1
fi

say "启动服务与定时器"
systemctl daemon-reload
systemctl enable --now "${SERVICE}.service"
systemctl enable --now qqbot-update.timer

say "当前状态"
systemctl --no-pager --lines=0 status "${SERVICE}.service" || true
systemctl --no-pager list-timers qqbot-update.timer || true

cat <<EOF

装好了。之后你会用到的东西：
  看服务        systemctl status ${SERVICE}
  看更新记录    tail -f ${APP_DIR}/update.log
  手动查版本    ${APP_DIR}/update.sh --check
  手动更一次    sudo -u ${RUN_USER} ${APP_DIR}/update.sh

你要做的只有：本地改代码 → 打 tag 推上去。服务器会自己在 10 分钟内换好版本。
EOF
