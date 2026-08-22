#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""飞书 → 防火墙 Agent 桥接 v2：控制台全任务类型 + 变更审批闭环"""
import json, os, subprocess, sys, time, urllib.request

LARK = os.environ.get("LARK_CLI", "lark-cli")  # 可 LARK_CLI 环境变量指定绝对路径；未配置则 PATH 查找
CHAT_ID = "oc_0238b0ea1d6d7a74180cfce85b18cf67"
SIGNATURE = "—— WorkBuddy 防火墙 Agent"
BASE = "http://localhost:8080"
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".state", "feishu-last.ts")
# 审批会话：{taskId: {"template": ..., "name": ...}}，用户回复"批准/确认"时用
PENDING = {}

TRIGGERS = ["防火墙", "巡检", "查", "PA-440", "PA440", "威胁", "策略", "状态",
            "清单", "资产", "inventory", "NAT", "许可", "会话", "流量", "接口", "地址对象", "区域", "VPN", "WildFire", "内容库",
            "审计", "谁改的", "变更记录", "诊断", "排查", "为什么", "创建", "封禁", "删除",
            "批准", "确认", "拒绝", "取消"]

def http_json(path, data=None):
    # 携带 internal_token（环境变量优先，否则读 cfgs/auth.json）——WebUI 开启认证后 bridge 才能调用 API
    token = os.environ.get("PANOS_WEB_INTERNAL_TOKEN", "")
    if not token:
        try:
            auth = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cfgs", "auth.json")))
            token = auth.get("internal_token", "")
        except Exception:
            token = ""
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        if data is None:
            req = urllib.request.Request(BASE + path, headers=headers)
        else:
            headers["Content-Type"] = "application/json"
            req = urllib.request.Request(BASE + path, data=json.dumps(data).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": "WebUI 不可达: " + str(e)}

def run_cli(args):
    env = dict(os.environ)
    # lark-cli 是 `#!/usr/bin/env node` 的 wrapper，调用时 PATH 必须有 node 可执行。
    parts = []
    if os.path.dirname(LARK):
        parts.append(os.path.dirname(LARK))
    node_bin = os.environ.get("NODE_BIN", "")
    if node_bin and os.path.dirname(node_bin):
        parts.append(os.path.dirname(node_bin))
    if parts:
        env["PATH"] = ":".join(parts) + ":" + env.get("PATH", "")
    try:
        out = subprocess.run([LARK] + args, capture_output=True, text=True, timeout=30, env=env)
        return json.loads(out.stdout or "{}")
    except Exception as e:
        return {}

def list_messages(limit=30):
    r = run_cli(["im", "+chat-messages-list", "--chat-id", CHAT_ID, "--order", "desc", "--limit", str(limit)])
    if not r.get("ok"):
        return []
    out = []
    for m in r.get("data", {}).get("messages", []):
        c = m.get("content_text") or m.get("content", "")
        mt = m.get("msg_type", "")
        if not c:
            continue
        try:
            cj = json.loads(c)
            # 富文本 post 类型（移动端常见）：提取所有 text 节点拼接
            if mt == "post" and isinstance(cj, dict):
                parts = []
                def walk(node):
                    if isinstance(node, dict):
                        for k, v in node.items():
                            if k == "text":
                                parts.append(v)
                            else:
                                walk(v)
                    elif isinstance(node, list):
                        for it in node:
                            walk(it)
                walk(cj.get("content", cj))
                c = " ".join(p for p in parts if isinstance(p, str))
            elif isinstance(cj, dict):
                c = cj.get("text", c) if isinstance(cj.get("text"), str) else c
        except Exception:
            pass
        if not c or not c.strip():
            continue
        out.append({"id": m.get("message_id", ""), "time": m.get("create_time", ""), "text": c.strip()})
    return out

def send_reply(text):
    r = run_cli(["im", "+messages-send", "--chat-id", CHAT_ID, "--msg-type", "text", "--text", text])
    return r.get("ok", False)

def wait_task(task_id, timeout=90):
    """轮询任务直到 done/failed"""
    end = time.time() + timeout
    while time.time() < end:
        d = http_json("/api/tasks")
        for t in d.get("tasks", []):
            if t["id"] == task_id:
                if t["status"] in ("done", "failed", "cancelled"):
                    return t
        time.sleep(5)
    return None

def summarize_task(t):
    status = t.get("status", "")
    typ = t.get("type", "")
    if status == "failed":
        return "❌ 任务失败: " + str(t.get("error", ""))[:300]
    r = t.get("result") or {}
    if typ == "query":
        parts = []
        for it in r.get("results", []):
            if it.get("error"):
                parts.append(it["tool"] + ": " + it["error"][:80])
                continue
            d = it.get("data") or {}
            arr = d.get("entry") if isinstance(d, dict) else None
            if isinstance(arr, list):
                parts.append(it["tool"].replace("get_", "") + " " + str(len(arr)) + " 条")
                if arr and isinstance(arr[0], dict):
                    s0 = {k: v for k, v in list(arr[0].items())[:4] if not k.startswith("_")}
                    parts.append("示例: " + json.dumps(s0, ensure_ascii=False)[:120])
            elif isinstance(d, dict):
                keys = ["hostname", "model", "sw-version", "enabled", "num-active", "kbps", "pps", "load average", "mem used"]
                brief = " ".join(f"{k}={d[k]}" for k in keys if k in d)
                if brief: parts.append(brief)
        return "\n".join(parts)[:1200]
    if typ == "inspect":
        return f"合规评级 {r.get('grade','?')}（{r.get('rate',0)}%）\n" + "\n".join(
            f"{'✅' if c.get('pass') else '❌'} {c.get('name')}" for c in r.get("checks", []))[:800]
    if typ == "diag":
        return f"【{r.get('title','诊断')}】\n结论: {r.get('verdict','')}\n置信度: {r.get('confidence','')}\n建议: {r.get('recommendation','')}"[:1000]
    if typ == "audit":
        return f"{r.get('title','审计')} · 共 {r.get('total',0)} 条\n" + "\n".join(
            f"{x['time']} | {x['admin']} | {x['cmd']} | {x['path'][:40]}" for x in (r.get("rows") or [])[:8])[:1200]
    if typ == "change":
        return str(r.get("detail") or r.get("needsManualCommit") or "变更完成")[:400]
    if typ == "chat":
        # 自由问答兜底：返回 LLM 完整回答（用户问什么答什么，而不是只回 status）
        return str(r.get("answer") or r.get("raw") or "（无回答）")[:1800]
    return str(status)

def _load_state():
    """游标：已处理 message_id 集合（秒级时间戳会丢同秒消息）。兼容旧数字格式。"""
    try:
        d = json.load(open(STATE))
        return set(d.get("seen", []))
    except Exception:
        try:
            ts = int(open(STATE).read().strip())
            return {"ts:" + str(ts)}  # 迁移占位：下次轮询前把所有旧消息视为已见
        except Exception:
            return set()

def _save_state(seen, msgs):
    for m in msgs:
        mid = m.get("id", "")
        if mid:
            seen.add(mid)
    with open(STATE, "w") as f:
        json.dump({"seen": list(seen)[-100:]}, f)

def main():
    msgs = list_messages(10)
    if not msgs:
        return
    seen = _load_state()
    # 兼容迁移：如果游标是旧数字时间戳，跳过所有更早的消息，避免重复处理历史
    migrate_ts = None
    for s in seen:
        if s.startswith("ts:"):
            migrate_ts = int(s[3:])
    seen = {s for s in seen if not s.startswith("ts:")}

    for m in msgs:
        # 单条消息独立 try/except：任一条处理失败（如时间格式异常）不阻塞后续消息，
        # 且失败消息也标记 seen，避免无限重试同一消息导致其他消息永远不执行。
        try:
            if SIGNATURE in m["text"]:
                continue
            mid = m.get("id", "")
            try:
                ts = int(m["time"].replace(" ", "").replace("-", "").replace(":", ""))
            except Exception:
                ts = 0  # 时间解析失败：不按时间过滤，仅靠 seen 去重
            if mid and mid in seen:
                continue
            if migrate_ts and ts and ts <= migrate_ts:
                continue
            text = m["text"]
        except Exception as e:
            print("skip message (parse fail):", e)
            seen.add(m.get("id", ""))
            continue
        if mid:
            seen.add(mid)  # 提前标记已见：即使后续处理中断也不会重复处理

        # 1) 变更审批流：批准/确认/拒绝（PENDING 丢失时从控制台兜底查找）
        if any(k in text for k in ("批准", "确认", "拒绝")):
            tid = None
            if PENDING:
                tid = list(PENDING.keys())[-1]
            else:
                try:
                    tlist = http_json("/api/tasks").get("tasks", [])
                    for t in reversed(tlist):
                        if t.get("status") == "awaiting_approval":
                            tid = t.get("id")
                            break
                except Exception:
                    pass
            if tid:
                act = "reject" if "拒绝" in text else ("approve" if "批准" in text else "confirm")
                if act == "approve":
                    d = http_json(f"/api/task/{tid}/approve", {})
                    if d.get("error"):
                        send_reply(f"⚠ {d['error']}\n{SIGNATURE}")
                    else:
                        # 闭环：approve 写候选后自动 confirm 提交，避免任务停在 awaiting_commit
                        time.sleep(3)
                        http_json(f"/api/task/{tid}/confirm", {})
                        t = wait_task(tid)
                        send_reply("【PA-440 Agent】\n" + (summarize_task(t) if t else "任务超时，请在控制台查看") + "\n" + SIGNATURE)
                elif act == "reject":
                    http_json(f"/api/task/{tid}/reject", {})
                    send_reply(f"【PA-440 Agent】任务 #{tid} 已拒绝\n{SIGNATURE}")
                else:  # confirm
                    http_json(f"/api/task/{tid}/confirm", {})
                    t = wait_task(tid)
                    send_reply("【PA-440 Agent】\n" + (summarize_task(t) if t else "任务超时，请在控制台查看") + "\n" + SIGNATURE)
                PENDING.clear()
            else:
                send_reply("没有待审批的变更任务。可先发送「创建地址对象 xxx 值 1.2.3.4」发起变更\n" + SIGNATURE)
            continue

        # 2) 普通任务：不再用 TRIGGERS 硬过滤（移动端消息常不含关键词导致静默丢弃）——
        #    全部交给后端 LLM 意图分类 + 自由问答兜底，任何消息都有响应。
        #    仅跳过纯闲聊/表情等明显非运维消息（避免浪费 LLM 调用）。
        if text.strip() in ("test", "测试", "你好", "hello", "hi", "在吗", "谢谢", "感谢"):
            send_reply("【PA-440 Agent】你好，发送防火墙相关指令即可（如：设备状态 / 安全策略 / 完整巡检 / 封禁 1.2.3.4）\n" + SIGNATURE)
            continue
        print("trigger:", text[:60])
        res = http_json("/api/task", {"query": text, "source": "feishu"})
        if res.get("error"):
            send_reply("【PA-440 Agent】" + str(res["error"])[:400] + "\n" + SIGNATURE)
            continue
        tid = res.get("taskId")
        if res.get("status") == "awaiting_approval":
            # 变更：显示计划，等待用户批准
            PENDING[tid] = {"template": res.get("plan", "")}
            send_reply(f"【PA-440 Agent】变更计划：{res.get('plan','')}\n回复「批准」继续执行\n{SIGNATURE}")
        else:
            t = wait_task(tid)
            if t:
                send_reply("【PA-440 Agent】\n" + summarize_task(t) + "\n" + SIGNATURE)
            else:
                send_reply("【PA-440 Agent】任务超时，请在控制台查看\n" + SIGNATURE)

    _save_state(seen, msgs)

if __name__ == "__main__":
    if "--daemon" in sys.argv:
        print("[feishu-bridge] v2 daemon started, polling every 60s")
        while True:
            try:
                main()
            except Exception as e:
                print("loop error:", e)
            try:
                open("/tmp/feishu-bridge.heartbeat", "w").write(str(int(time.time())))
            except Exception:
                pass
            time.sleep(15)
    else:
        main()
