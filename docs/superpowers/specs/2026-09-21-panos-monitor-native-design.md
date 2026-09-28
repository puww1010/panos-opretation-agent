# PAN-OS 深度健康巡检：路线 B

用户已批准路线 B 和全部三批工作。本文记录实施边界，不替代真实设备验收。

## 范围

保留现有完整巡检，新增深度健康巡检。检查规则参考 MIT 许可的 puww1010/panos-monitor，固定版本 09146cd68e394a0795c6296dfde30dea7139be0b。运行时不下载或执行该仓库代码，不启用 Python 服务，不增加密钥存储。所有采集使用现有 PAN-OS Adapter/MCP，Task Service 管理状态、取消、持久化和审计。

第一批：system/environmentals/resources/sessions/interfaces/ha/license/certificates。
第二批：disk_space/logdb_quota/software_status/global_counters/app_stats/discard_sessions/transceivers/routing/rule_hits/zone_protection/decryption/threat_logs/ha_diagnostics/jobs/edl/fqdn/vpn/globalprotect/dns_proxy/user_id/sdwan。
第三批：中文分类结果、证据、覆盖率、进度、JSON 和中文报告导出、回归和真实只读验证。

## 契约

- 新任务类型 `monitor`。请求使用固定检查 ID、分类或全部；自然语言常用入口不依赖 LLM，未知或混合写操作意图不推测执行。
- 检查模块只获取注入的 `read(sourceId)`，不能执行任意命令或接触密钥。采集器将固定 sourceId 映射到现有工具/预审查 XML；不把用户输入拼成 XML。
- 每项结果：id、category、label、collection（ok/partial/error/unsupported/not_applicable/unknown）、severity（ok/info/warning/critical/unknown）、findings、sources、observedAt、durationMs。
- finding：metric、value、unit、severity、message、recommendation，可附 plane/window；没有可解析证据时不可报告健康。
- 报告区分执行状态、健康结论、检查覆盖率；任一缺失均可见。Task 状态仍使用既有 pending/running/done/failed/cancelled，部分完成写入报告 executionStatus，不破坏既有治理。
- 全量检查逐项执行，每设备最多一个深度巡检；单项与全局有时限，取消不允许迟到结果覆盖 cancelled。失败消息脱敏，报告不保存完整配置、密钥或原始异常堆栈。
- 采集时间窗口明确，威胁计数注明读取上限与覆盖不完整；绝不把 50 条样本等同完整窗口。MP 与 DP 指标分开，不用 load average 冒充 CPU 百分比。不做未定义时间间隔的计数器速率判断。
- HTML 显示及导出必须转义；导出由认证 API 按任务 ID 读取，不接受任意文件路径。默认不向第三方 LLM 发送巡检证据。
- 未启用 HA、VPN、SD-WAN 仅在有明确证据时记为不适用；不支持命令、采集失败和未知结构分别可见。
- 保留现有用户未提交内容，尤其认证、登录页、配置和任务文件。只增量修改 UI 接入点。

## 验收

29 项均有正常/风险/缺失输入测试；特殊回归包括 FIN+FAIL、SD-WAN Warning 不升级、缺失不全绿、无凭据输出、只读命令白名单、正确设备目标、取消/超时/恢复/审计、报告权限/XSS。真实设备无法提供的功能不冒称实测通过。不上定时调度，不做防火墙配置写入，不变更云端网络。
