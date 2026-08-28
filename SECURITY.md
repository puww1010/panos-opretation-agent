# Security Policy

## Supported Versions

内部试用阶段维护 `5.1.x`。正式部署前应完成 SSO、角色权限、会话空闲超时、设备管理网隔离与密钥轮换评审。

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

请不要在 issue、聊天记录、截图、日志或提交中粘贴 API Key、会话令牌、设备凭据、飞书凭据或完整运行时配置。发现疑似泄露时，应立即撤销/轮换对应凭据，并移除公开位置中的内容。

内部试用版的安全边界：

- 所有 API 必须通过有效会话认证；不要以“前端隐藏按钮”代替服务端授权。
- 任务的批准、拒绝、取消和 commit 确认由服务端校验状态转换；变更计划指纹不一致时必须重新生成计划。
- `cfgs/auth.json`、`cfgs/tasks.json`、`cfgs/llm-choice.json`、`cfgs/audit-events.json` 与真实设备/模型配置均为运行时敏感文件，不得提交。
- 当前内部测试按产品决定保持空闲自动退出关闭；这不是生产安全基线，外部部署前必须重新启用并验证会话超时策略。
