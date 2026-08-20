#!/bin/bash
# ============================================================
# 构建 PAN-OS Agent.app — macOS 自包含安装包（内嵌 Node 运行时）
# 用法: bash build-app.sh
# 产物: dist/PAN-OS Agent.app（双击即用；可拖到 /Applications）
# ============================================================
set -e
PROJ="$(cd "$(dirname "$0")/.." && pwd)"          # 项目根
OUT="$PROJ/dist"
APP="$OUT/PAN-OS Agent.app"
NODE_SRC="${NODE_SRC:-/Users/vpeng/.workbuddy/binaries/node/versions/22.22.2/bin/node}"

rm -rf "$OUT"
mkdir -p "$APP/Contents/MacOS" \
         "$APP/Contents/Resources/console" \
         "$APP/Contents/Resources/node-dir"

echo "==> 1/4 复制 Node 运行时 ($(du -h "$NODE_SRC" | cut -f1))"
cp "$NODE_SRC" "$APP/Contents/Resources/node-dir/node"
chmod +x "$APP/Contents/Resources/node-dir/node"

echo "==> 2/4 复制控制台项目（webui/mcp/脚本，含全部依赖）"
cp -R "$PROJ/webui"          "$APP/Contents/Resources/console/webui"
cp -R "$PROJ/mcp"            "$APP/Contents/Resources/console/mcp"
[ -d "$PROJ/.state" ] && cp -R "$PROJ/.state" "$APP/Contents/Resources/console/.state" || true
cp "$PROJ/panagent-supervisor.py" "$APP/Contents/Resources/console/"
cp "$PROJ/feishu-bridge.py"       "$APP/Contents/Resources/console/"

# ⚠️ 安全：绝不把开发机的真实凭据（LLM API Key / 防火墙 API Key）打进安装包。
# 用空模板替换，客户首次启动后自行填入（webui 的 模型配置 弹窗 / cfgs/firewalls.json）。
echo "==> 2b 敏感配置脱敏（用空 key 模板替换，避免泄露开发凭据）"
mkdir -p "$APP/Contents/Resources/console/cfgs"
# firewalls.json → 空模板（客户填自己的 PA 设备 IP + API key）
python3 - "$PROJ/cfgs/firewalls.json" "$APP/Contents/Resources/console/cfgs/firewalls.json" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(src))
    fws = d.get("firewalls", [])
    for f in fws:
        f["api_key"] = ""  # 客户填写
    json.dump({"firewalls": fws}, open(dst, "w"), ensure_ascii=False, indent=2)
    print("    cfgs/firewalls.json 已脱敏（", len(fws), "台设备占位）")
except Exception as e:
    json.dump({"firewalls": []}, open(dst, "w"))
    print("    警告: 脱敏 firewalls.json 失败，写入空占位:", e)
PY
# webui/llm-config.json → 保留 provider 结构但清空所有 key
python3 - "$PROJ/webui/llm-config.json" "$APP/Contents/Resources/console/webui/llm-config.json" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(src))
    for k, v in d.get("providers", {}).items():
        if isinstance(v, dict):
            v["key"] = ""
    d.pop("_default", None)
    json.dump(d, open(dst, "w"), ensure_ascii=False, indent=2)
    print("    webui/llm-config.json 已脱敏（provider 结构保留，key 清空）")
except Exception as e:
    json.dump({"providers": {}}, open(dst, "w"))
    print("    警告: 脱敏 llm-config.json 失败，写入空占位:", e)
PY

echo "==> 3/4 写 Info.plist"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>            <string>PAN-OS Agent</string>
  <key>CFBundleDisplayName</key>      <string>PAN-OS Agent</string>
  <key>CFBundleIdentifier</key>       <string>com.panagent.console</string>
  <key>CFBundleVersion</key>          <string>4.1.0</string>
  <key>CFBundleShortVersionString</key><string>4.1.0</string>
  <key>CFBundleExecutable</key>       <string>launcher</string>
  <key>CFBundlePackageType</key>      <string>APPL</string>
  <key>LSMinimumSystemVersion</key>   <string>12.0</string>
  <key>NSHighResolutionCapable</key>  <true/>
  <key>LSUIElement</key>              <true/>
</dict>
</plist>
PLIST

echo "==> 4/4 写 launcher（启动控制台 + 打开浏览器）"
cat > "$APP/Contents/MacOS/launcher" <<'EOF'
#!/bin/bash
# PAN-OS Agent 启动器：用内嵌 Node 启动 supervisor，并打开控制台页面
RES="$(cd "$(dirname "$0")/../Resources" && pwd)"
NODE="$RES/node-dir/node"
CONSOLE="$RES/console"
LOG="/tmp/panagent-app.log"

export NODE_BIN="$NODE"
export PATH="$RES/node-dir:$PATH"
[ -n "$LARK_CLI" ] && export LARK_CLI

# 若控制台已在运行则直接开浏览器
if lsof -iTCP:8080 -sTCP:LISTEN -n 2>/dev/null | grep -q node; then
  open "http://localhost:8080"
  exit 0
fi

cd "$CONSOLE"
nohup "$NODE" panagent-supervisor.py --daemon >>"$LOG" 2>&1 &
sleep 3
open "http://localhost:8080"
EOF
chmod +x "$APP/Contents/MacOS/launcher"

echo "==> 完成: $APP"
du -sh "$APP"
echo "（拖到 /Applications 即可；控制台监听 8080，页面自动打开）"
