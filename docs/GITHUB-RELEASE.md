# GitHub 发布操作手册

> 本仓库已 `git init` 并完成首次提交（main 分支，73 个文件），敏感配置已通过 `.gitignore` 排除。
> 按下面步骤即可推到 GitHub 并对外发布。

---

## 1. 创建 GitHub 远端仓库

在 github.com 上新建空仓库（**不要勾选** README / .gitignore / LICENSE，避免冲突），得到地址如：

```
https://github.com/puww1010/panos-agent-console.git
```

## 2. 关联远端并推送

```bash
# 在项目根目录执行
git remote add origin https://github.com/puww1010/panos-agent-console.git
git push -u origin main
```

> 推送前会要求 GitHub 认证：HTTPS 用 Personal Access Token（Settings → Developer settings → Tokens → Generate，勾选 `repo` 权限），SSH 用 `ssh-keygen` + 公钥配置。

## 3. 推送后安全自查（必做）

```bash
# 1) 仓库里绝不能出现真实 API Key
git grep -n "sk-" origin/main -- "*.json" 2>/dev/null | grep -v example || echo "✅ 无泄露"

# 2) 确认真实配置不在仓库
git ls-files | grep -E "llm-config\.json|firewalls\.json" | grep -v example || echo "✅ 无真实配置入库"
```

**⚠️ 如果发现历史提交里有 key**：key 已失效的情况直接忽略；仍在用的必须立刻去对应平台（DeepSeek/百炼/Kimi）**吊销并重新生成**，然后 `git rm` + 重提交。

## 4. 后续日常维护

```bash
# 查看状态 / 提交
git status
git add -A
git commit -m "feat: 说明本次改动"
git push

# 拉取远端
git pull --rebase

# 打版本标签（配合 PACKAGING-DEPLOY.md 的发布流程）
git tag v4.2.0
git push --tags
```

## 5. 常用 git 速查

| 操作 | 命令 |
|---|---|
| 放弃未提交改动 | `git checkout -- .` |
| 查看上次提交改了什么 | `git show --stat HEAD` |
| 撤销上次提交（保留改动） | `git reset --soft HEAD~1` |
| 查看忽略规则是否生效 | `git check-ignore -v webui/llm-config.json` |
| 本地是否干净 | `git status --short`（空 = 干净） |

## 6. 已知仓库内容

```
73 个文件入库，无 node_modules / dist / reports / 真实配置
├── README.md                 # 项目介绍 + 启动 + GitHub 发布说明
├── .gitignore                # 敏感/依赖/产物排除
├── docs/                     # DEPLOY / 规格 / 打包部署 3 份文档
├── webui/                    # 控制台源码（6 文件 + llm-config.example.json）
├── standalone/               # 零依赖部署包（8 文件）
├── mcp/panos-mcp/            # MCP 层源码（46 文件，含 tsconfig/package.json）
├── cfgs/firewalls.example.json
├── scripts/build-app.sh      # macOS 打包（自动脱敏）
├── feishu-bridge.py / panagent-supervisor.py
└── diagrams/                 # 架构图
```
