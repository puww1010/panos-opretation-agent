#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""飞书 → 防火墙 Agent 桥接 v3（零 WorkBuddy 依赖）：纯飞书开放平台 API，无 lark-cli"""
# 需要飞书自建应用（机器人），权限：im:message、im:message:readonly、im:chat
# 环境变量:
#   FEISHU_APP_ID / FEISHU_APP_SECRET / FEISHU_CHAT_ID（必填，可收发）
#   WEBUI_BASE（默认 http://localhost:8080）
import json, os, sys, time, urllib.request, urllib.error

APP_ID = os.environ.get("FEISHU_APP_ID", "")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "")
CHAT_ID = os.environ.get("FEISHU_CHAT_ID", "")
SIGNATURE = "—— 防火墙 Agent"
BASE = os.environ.get("WEBUI_BASE", "http://localhost:8080")
STATE = os.path.expanduser("~/.panos-feishu-last.ts")
POLL = int(os.environ.get("POLL_SECONDS", "60"))
PENDING = {}  # 审批会话

TRIGGERS = ["防火墙", "巡检", "查", "PA-440", "PA440", "威胁", "策略", "状态",
            "NAT", "许可", "会话", "流量", "接口", "地址对象", "区域", "VPN", "WildFire", "内容库",
            "审计", "谁改的", "变更记录", "诊断", "排查", "为什么", "创建", "封禁", "删除",
            "批准", "确认", "拒绝", "取消"]

_token = None
_token_ts = 0

def api(path, data=None, method=None):
    """调用飞书开放平台 API，自动带 tenant_access_token"""
    global _token, _token_ts
    if not _token or time.time() - _token_ts > 5400:
        body = json.dumps({"app_id": APP_ID, "app_secret": APP_SECRET}).encode()
        req = urllib.request.Request("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
                                     data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            o = json.loads(r.read().decode())
        if o.get("code") != 0:
            raise RuntimeError("获取 token 失败: " + o.get("msg", "?"))
        _token = o["tenant_access_token"]
        _token_ts = time.time()
    url = "https://open.feishu.cn" + path
    headers = {"Authorization": "Bearer " + _token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers=headers, method=method or ("POST" if data is not None else "GET"))
    with urllib.request.urlopen(req, timeout=15) as r:
        o = json.loads(r.read().decode())
    if o.get("code") != 0:
        raise RuntimeError("飞书 API 错误: " + o.get("msg", "?"))
    return o

def list_messages(limit=10):
    msgs = []
    page = None
    for _ in range(3):
        path = (f"/open-apis/im/v1/messages?container_id_type=chat&container_id={CHAT_ID}"
                f"&page_size={limit}&sort_type=ByCreateTimeDesc")
        if page: path += "&page_token=" + page
        o = api(path)
        for m in o.get("data", {}).get("items", []):
            if m.get("msg_type") != "text":
                continue
            try:
                c = json.loads(m.get("body", {}).get("content", "{}"))
                text = c.get("text", "")
            except Exception:
                continue
            if not text:
                continue
            msgs.append({"id": m.get("message_id", ""), "time": m.get("create_time", "0"), "text": text})
        page = o.get("data", {}).get("has_more") and o.get("data", {}).get("page_token")
        if not page:
            break
    return msgs

def send_reply(text):
    api("/open-apis/im/v1/messages?receive_id_type=chat_id",
        {"receive_id": CHAT_ID, "msg_type": "text", "content": json.dumps({"text": text})})
    return True

def http_json(path, data=None):
    try:
        if data is None:
            req = urllib.request.Request(BASE + path)
        else:
            req = urllib.request.Request(BASE + path, data=json.dumps(data).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": "WebUI 不可达: " + str(e)}

def wait_task(task_id, timeout=90):
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
    return str(status)

def main():
    msgs = list_messages(10)
    if not msgs:
        return
    try:
        last_ts = int(open(STATE).read().strip())
    except Exception:
        last_ts = 0
    latest = max(int(m["time"]) for m in msgs)

    for m in msgs:
        if SIGNATURE in m["text"]:
            continue
        ts = int(m["time"])
        if ts <= last_ts:
            continue
        text = m["text"]

        # 1) 变更审批流
        if any(k in text for k in ("批准", "确认", "拒绝")):
            if PENDING:
                tid = list(PENDING.keys())[-1]
                act = "approve" if "批准" in text else ("confirm" if "确认" in text else "reject")
                d = http_json(f"/api/task/{tid}/{act}", {})
                if d.get("error"):
                    send_reply(f"⚠ {d['error']}\n{SIGNATURE}")
                else:
                    if act in ("approve", "confirm"):
                        t = wait_task(tid)
                        if t:
                            send_reply("【防火墙 Agent】\n" + summarize_task(t) + "\n" + SIGNATURE)
                        else:
                            send_reply("【防火墙 Agent】任务超时，请在控制台查看\n" + SIGNATURE)
                    else:
                        send_reply(f"【防火墙 Agent】任务 #{tid} 已拒绝\n{SIGNATURE}")
                PENDING.clear()
            else:
                send_reply("没有待审批的变更任务。可先发送「创建地址对象 xxx 值 1.2.3.4」发起变更\n" + SIGNATURE)
            break

        # 2) 普通任务
        if not any(k in text for k in TRIGGERS):
            continue
        print("trigger:", text[:60])
        res = http_json("/api/task", {"query": text})
        if res.get("error"):
            send_reply("【防火墙 Agent】" + str(res["error"])[:400] + "\n" + SIGNATURE)
            continue
        tid = res.get("taskId")
        if res.get("status") == "awaiting_approval":
            PENDING[tid] = {"template": res.get("plan", "")}
            send_reply(f"【防火墙 Agent】变更计划：{res.get('plan','')}\n回复「批准」继续执行\n{SIGNATURE}")
        else:
            t = wait_task(tid)
            if t:
                send_reply("【防火墙 Agent】\n" + summarize_task(t) + "\n" + SIGNATURE)
            else:
                send_reply("【防火墙 Agent】任务超时，请在控制台查看\n" + SIGNATURE)
        break

    with open(STATE, "w") as f:
        f.write(str(latest))

if __name__ == "__main__":
    if not (APP_ID and APP_SECRET and CHAT_ID):
        print("❌ 需要环境变量 FEISHU_APP_ID / FEISHU_APP_SECRET / FEISHU_CHAT_ID（飞书自建应用机器人）")
        sys.exit(1)
    if "--daemon" in sys.argv:
        print(f"[feishu-bridge] v3 daemon started（纯 API），轮询 {POLL}s，群 {CHAT_ID}")
        while True:
            try:
                main()
            except Exception as e:
                print("loop error:", e)
            try:  # 心跳：供控制台判断 daemon 存活（每轮必写）
                open("/tmp/feishu-bridge.heartbeat", "w").write(str(int(time.time())))
            except Exception:
                pass
            time.sleep(POLL)
    else:
        main()
