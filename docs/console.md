# CodeGuard 控制台（Console）

面向 PR 安全闸门的 Web 控制台：仓库授权、任务列表、CVE 看板、审计检索，以及
**基于 SSE 的 Agent 执行链路实时展示**。

前端 `frontend/`（Vue3 + TypeScript + ECharts），后端复用现有 FastAPI 服务，
新增 4 张 SQLite 表与 12 个只读/轻写接口。

---

## 1. 数据从哪来

原项目的报告是「一次扫描一个 JSON 文件」（`LocalFileReportStorage`），无法回答
「列出最近 30 次扫描」「画 30 天趋势」这类问题。控制台因此新增四张表，全部落在
`data/codeguard.db`（与审计日志同库，不新增数据库实例）：

| 表 | 作用 | 关键字段 |
|---|---|---|
| `repos` | GitHub App 授权的仓库 | `repo_full_name`(unique)、`installation_id`、`enabled` |
| `scans` | 一次扫描的元信息与结论 | `scan_id`(PK)、`status`、`verdict`、`blocker_count`、`cve_count`、`duration_ms` |
| `findings` | 展开后的发现项 | `scan_id`、`finding_type`、`cve_id`、`package_name`、`severity`、`verdict` |
| `agent_events` | Agent 链路事件（SSE 回放源） | `scan_id`、`agent`、`status`、`duration_ms`、`payload` |

写入方是 `src/monitoring/scan_recorder.py`，它由 Celery 任务在阶段边界调用：

```
analysis_main_task  → scan_started
preprocess_task     → preprocess finished/degraded
security_chain_task → security started/finished, conflict started/finished
migration_task      → migration started/finished/skipped
report_aggregation_task → reporter started/finished, scan_finished
```

硬约束：**记录器永不抛异常**。数据库被锁、Redis 掉线，只丢遥测，不影响安全主链。

---

## 2. API

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/v1/scans` | 分页列表，支持 `repo` / `status` / `verdict` / `since` |
| GET | `/api/v1/scans/{id}` | 详情：严重级分布 + Agent 时间线 + 发现项 |
| GET | `/api/v1/scans/{id}/findings` | 发现项，支持严重级 / 裁决 / 类型过滤 |
| GET | `/api/v1/scans/{id}/report` | 完整报告（文件优先，Redis 兜底） |
| GET | `/api/v1/scans/{id}/stream` | **SSE** 实时链路 |
| GET | `/api/v1/dashboard/{summary,severity,trend,top-packages}` | 概览与 CVE 看板 |
| GET | `/api/v1/repos` | 已授权仓库 |
| POST | `/api/v1/repos` | 手动登记（离线演示用） |
| PATCH | `/api/v1/repos` | 启停仓库 |
| GET | `/api/v1/repos/install/url` | GitHub App 安装地址 |
| POST/GET | `/api/v1/repos/install/callback` | 安装回调（JSON / 浏览器落地页） |
| POST | `/api/v1/repos/install/sync/{installation_id}` | 重新拉取仓库列表 |
| GET | `/api/v1/audit` | 审计检索（分页 + 条件） |
| GET | `/api/v1/audit/verify` | 重算哈希链，检测篡改 |

鉴权：`CODEGUARD_API_KEY` 未设置时控制台接口放行（本地演示）；设置后要求
`X-API-Key`，与 `/analyze` 的 secure-by-default 策略一致。

---

## 3. SSE 协议

通道：Redis `scan:{scan_id}:events`；同时每条事件落 `agent_events`。

```text
id: 7
data: {"event":"agent.finished","seq":7,"agent":"security","status":"finished",
       "duration_ms":812,"payload":{"vulnerabilities":19,"code_issues":3}}
```

- **先回放、后实时**：连接建立后先按 `Last-Event-ID`（或 `last_event_id` 查询参数）
  从 SQLite 补齐，再订阅 Redis。刷新页面不丢链路。
- **16 秒心跳**：`: ping\n\n`，避免中间层断开。
- **终态收流**：收到 `scan.finished` 或发现扫描已终态时关闭连接。
- **Redis 不可用降级**：改为每秒轮询 SQLite，单进程演示照常可看。

---

## 4. GitHub App 授权

`src/integrations/github_app.py` 实现真实的三步流：

1. RS256 JWT（`iss`=app_id，TTL 9 分钟，GitHub 上限 10 分钟）
2. `POST /app/installations/{id}/access_tokens` 换 installation token
3. token 内存缓存，到期前 60 秒刷新

配置项：`GITHUB_APP_ID`、`GITHUB_APP_PRIVATE_KEY`（PEM 内容或文件路径）、
`GITHUB_APP_SLUG`。未配置时接口返回 `configured: false`，控制台禁用「安装」按钮，
可走「手动登记仓库」完成离线演示。

---

## 5. 演示

```bash
# 一键起：Redis + API + Worker + 控制台
start-demo.bat

# 真实离线扫描（驱动四个 Agent，写入控制台数据）
python scripts/demo_scan.py --repo C:/Users/86186/fastapi_code --name encode/fastapi --pr 42

# 签名 webhook（走完整 PR 触发链路）
python scripts/emit_pr_webhook.py --repo encode/fastapi --pr 42
```

`demo_scan.py` 与 Celery 流水线调用同一批 Agent，唯一区别是不经过 Redis 队列，
因此控制台看到的是真实扫描结果，而不是种子数据。

---

## 6. 可选：启用 Semgrep 代码扫描

没装 Semgrep 时安全审计 Agent 会**降级**（只跑 CVE，code_issues 为空，
`degraded=true`），控制台会显示降级原因；按 fail-safe 策略，降级扫描的发现项
一律判阻断。装上之后代码扫描正常参与，阻断数只反映真实高危。

```bash
pip install -e ".[semgrep]"   # 推荐：装进运行 CodeGuard 的同一个环境
semgrep --version             # 确认可执行
```

查找顺序（见 `_locate_semgrep`）：

1. `CODEGUARD_SEMGREP_BIN` 环境变量（自定义安装位置，如 `--target` 安装）
2. `PATH` 中的 `semgrep`
3. 解释器同级目录（venv / conda env 根）
4. 解释器同级的 `Scripts`（Windows）或 `bin`（POSIX）子目录

第 4 条是为 conda base 环境补的：`sys.executable` 在 `<prefix>`，而 console script
装在 `<prefix>/Scripts`。少了这条，装好的 Semgrep 会被误判为缺失，扫描静默降级。

### 装到自定义目录时

`pip install --target D:/codeguard-semgrep semgrep` 这类安装没有 site-packages 记录，
启动脚本靠 `PYTHONPATH` 找包、靠 `PATH` 找 `pysemgrep`。扫描器会检测这种布局并自动
为**子进程**注入这两个变量（`_semgrep_env`），主进程环境不受影响。只需指个路径：

```bash
set CODEGUARD_SEMGREP_BIN=D:\codeguard-semgrep\bin\semgrep.exe
```

`start-demo.bat` 会在该目录存在时自动设置，无需手工配置。

### 装上之后行为有什么变化

| | 未装 Semgrep | 已装 Semgrep |
|---|---|---|
| `code_issues` | 恒为空 | 按 `config/semgrep/codeguard-rules.yml` 产出 |
| `degraded` | `true`，报告里写明原因 | `false` |
| 阻断口径 | fail-safe：所有发现项一律阻断 | 按 5 条裁决规则：直连依赖命中 CVE / 高危代码问题阻断，传递依赖默认豁免 |
