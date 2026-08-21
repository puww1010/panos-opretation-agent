#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PAN-OS Agent 常驻守护 supervisor：双进程保活 + double-fork 脱离会话。
用法:
  python3 panagent-supervisor.py            # 前台运行（调试）
  python3 panagent-supervisor.py --daemon   # 守护运行（脱离终端，推荐）
子进程任一崩溃，5 秒内自动拉起。由 launchd (com.panagent.supervisor) 开机自启。
"""
import os, sys, time, signal, subprocess, shutil, socket

# 项目根：默认取本文件所在目录的上级（独立部署时整个项目目录一起拷贝即可）
BASE = os.path.dirname(os.path.abspath(__file__))
# 运行时可用环境变量覆盖；默认用 PATH 中的 node/python（独立部署者自行保证）
PY = os.environ.get("PYTHON_BIN") or shutil.which("python3") or "python3"
NODE = os.environ.get("NODE_BIN") or shutil.which("node") or "node"
SYS_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
# lark-cli 与 node 的可执行目录（bridge 必须能找到；默认探测常见路径）
LARK_CLI = os.environ.get("LARK_CLI") or shutil.which("lark-cli") or ""
LARK_BIN_DIR = os.path.dirname(LARK_CLI) if LARK_CLI else ""
NODE_BIN_DIR = os.path.dirname(NODE) if NODE else ""
# 合并后的 PATH：保证 bridge 能 spawn lark-cli 与 node（SYS_PATH 里没有它们）
FULL_PATH = ":".join([p for p in [LARK_BIN_DIR, NODE_BIN_DIR, SYS_PATH] if p])

PROCS = {
    "console": {
        "cmd": [NODE, os.path.join(BASE, "webui", "server.js")],
        "env": {
            "NODE_PATH": os.path.join(BASE, "webui", "node_modules"),        # MCP SDK（控制台依赖）
            "PANOS_MCP_DIR": os.path.join(BASE, "mcp", "panos-mcp"),         # MCP server
            "PANOS_FIREWALLS_CONFIG": os.path.join(BASE, "cfgs", "firewalls.json"),  # 防火墙 key
            "PORT": "8080",
            "NODE_BIN": NODE,
            "PATH": FULL_PATH,
            # 清除 WorkBuddy 动态代理（会随会话失效）：本机直连飞书/PAN-OS 即可
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "http_proxy": "", "https_proxy": "",
            "ALL_PROXY": "", "all_proxy": "",
        },
        "log": "/tmp/panagent-console.out.log",
    },
    "bridge": {
        "cmd": [PY, os.path.join(BASE, "feishu-bridge.py"), "--daemon"],
        "env": {
            # lark-cli 与 node 路径必须显式注入，否则 bridge 拉不到消息（静默空转）
            "LARK_CLI": LARK_CLI,
            "NODE_BIN": NODE,
            "PATH": FULL_PATH,
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "http_proxy": "", "https_proxy": "",
            "ALL_PROXY": "", "all_proxy": "",
        },
        "log": "/tmp/panagent-feishu-bridge.out.log",
    },
}


def daemonize():
    """double-fork + setsid，完全脱离当前会话；父进程立即退出。"""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.chdir("/")
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)


def port_in_use(port):
    """端口是否被占用（仅本机回环探测）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def free_port(port):
    """spawn 前释放端口：kill 任何仍占用该端口的进程（先 SIGTERM 再 SIGKILL），
    并等待端口真正空闲。避免旧 node 未释放 8080 导致新进程 EADDRINUSE 后
    陷入'起不来→重启→又起不来'死循环（旧代码永不退出、新修复永不生效）。"""
    try:
        out = subprocess.run(["lsof", "-ti", "tcp:%d" % port],
                             capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        out = ""
    pids = [p for p in out.split() if p.strip().isdigit()] if out else []
    if not pids:
        return
    for pid in pids:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception:
            pass
    time.sleep(2)
    for pid in pids:
        try:
            os.kill(int(pid), 0)  # 仍存活？
            os.kill(int(pid), signal.SIGKILL)
        except Exception:
            pass
    # 等待端口真正空闲（最多 ~5s）
    for _ in range(10):
        if not port_in_use(port):
            break
        time.sleep(0.5)


def cleanup_stale_bridge():
    """清理上一代 supervisor 残留的 feishu-bridge 孤儿进程。
    否则每次重启 supervisor 都会堆积一个 bridge（历史曾堆积 13 个），
    多个 bridge 同时轮询飞书会重复处理消息。"""
    try:
        out = subprocess.run(["pgrep", "-f", "feishu-bridge.py"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        for pid in [p for p in out.split() if p.strip().isdigit()]:
            try:
                os.kill(int(pid), signal.SIGTERM)
            except Exception:
                pass
        time.sleep(2)
        for pid in [p for p in out.split() if p.strip().isdigit()]:
            try:
                os.kill(int(pid), 0)
                os.kill(int(pid), signal.SIGKILL)
            except Exception:
                pass
    except Exception as e:
        print("[supervisor] cleanup_stale_bridge warn:", e, flush=True)


def spawn(name, cfg):
    # console 占 8080：spawn 前先确保端口空闲，避免 EADDRINUSE 竞态
    if name == "console":
        free_port(8080)
    # bridge 单实例：spawn 前清理残留旧 bridge，避免多实例堆积
    if name == "bridge":
        cleanup_stale_bridge()
    log = open(cfg["log"], "a")
    env = dict(os.environ)
    env.update(cfg.get("env", {}))
    p = subprocess.Popen(cfg["cmd"], stdout=log, stderr=log,
                         stdin=subprocess.DEVNULL, env=env)
    print("[supervisor] %s started pid=%d" % (name, p.pid), flush=True)
    return p


def main():
    procs = {}
    for name, cfg in PROCS.items():
        procs[name] = spawn(name, cfg)
    print("[supervisor] supervising: %s" % ", ".join(PROCS.keys()), flush=True)
    while True:
        time.sleep(5)
        for name, cfg in PROCS.items():
            p = procs.get(name)
            if p is None or p.poll() is not None:
                print("[supervisor] %s exited, restarting in 2s..." % name, flush=True)
                time.sleep(2)
                procs[name] = spawn(name, cfg)


if __name__ == "__main__":
    if "--daemon" in sys.argv:
        daemonize()
        logf = open("/tmp/panagent-supervisor.log", "a")
        os.dup2(logf.fileno(), 1)
        os.dup2(logf.fileno(), 2)
        main()
    else:
        main()
