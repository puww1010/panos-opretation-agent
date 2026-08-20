#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PAN-OS Agent 常驻守护 supervisor：双进程保活 + double-fork 脱离会话。
用法:
  python3 panagent-supervisor.py            # 前台运行（调试）
  python3 panagent-supervisor.py --daemon   # 守护运行（脱离终端，推荐）
子进程任一崩溃，5 秒内自动拉起。由 launchd (com.panagent.supervisor) 开机自启。
"""
import os, sys, time, subprocess, shutil

# 项目根：默认取本文件所在目录的上级（独立部署时整个项目目录一起拷贝即可）
BASE = os.path.dirname(os.path.abspath(__file__))
# 运行时可用环境变量覆盖；默认用 PATH 中的 node/python（独立部署者自行保证）
PY = os.environ.get("PYTHON_BIN") or shutil.which("python3") or "python3"
NODE = os.environ.get("NODE_BIN") or shutil.which("node") or "node"
SYS_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"

PROCS = {
    "console": {
        "cmd": [NODE, os.path.join(BASE, "webui", "server.js")],
        "env": {
            "NODE_PATH": os.path.join(BASE, "webui", "node_modules"),        # MCP SDK（控制台依赖）
            "PANOS_MCP_DIR": os.path.join(BASE, "mcp", "panos-mcp"),         # MCP server
            "PANOS_FIREWALLS_CONFIG": os.path.join(BASE, "cfgs", "firewalls.json"),  # 防火墙 key
            "PORT": "8080",
            "PATH": SYS_PATH,
            # 清除 WorkBuddy 动态代理（会随会话失效）：本机直连飞书/PAN-OS 即可
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "http_proxy": "", "https_proxy": "",
            "ALL_PROXY": "", "all_proxy": "",
        },
        "log": "/tmp/panagent-console.out.log",
    },
    "bridge": {
        "cmd": [PY, os.path.join(BASE, "feishu-bridge.py"), "--daemon"],
        "env": {
            # lark-cli 路径由 LARK_CLI 环境变量指定（可选，飞书桥非必须）
            "PATH": SYS_PATH,
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


def spawn(name, cfg):
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
