# K8s Lab Platform

面向课程教学的模板驱动实验环境平台。管理员发布模板，教师通过模板创建实验环境并分配给课程内的小组或学生，平台按模板调用插件，执行创建、启停、重启、删除及其他插件支持的操作。

## 项目状态

**仓库的控制面入口为 `python -m control_plane`，提供 HTTP API、模板驱动界面和 WebSSH。管理员发布模板，教师创建及分配环境，学生按实时授权运行模板动作、查看环境凭据并使用终端。环境创建使用配额事务，插件调用和会话建立通过持久化执行内核完成。浏览器验收环境与实测范围见 [P5 验收记录](tests_control_plane/browser/P5_ACCEPTANCE.md)。**

仍在运行旧部署的站点，切换前须完成[旧部署退役检查](docs/architecture.md#91-旧部署退役与硬切换前置条件)。

## 目标与角色

| 角色 | 职责 |
| --- | --- |
| 管理员 | 管理用户、已加载插件的实例配置、模板、实验环境及资源、教师配额 |
| 教师 | 创建课程、小组和平台学生账号；选择已发布模板创建环境；在同一课程内分配给多个组和/或学生；管理自己的环境，旁观和接管学生 WebSSH |
| 学生 | 管理本人允许修改的信息；仅访问直接分配或通过组分配获得的环境，执行模板向学生开放的动作，查看授权环境凭据和使用 WebSSH |

教师不编写模板、不配置底层基础设施、不直接调用插件。学生没有创建或删除环境、分配环境、管理模板和插件的权限。

学生账号可以跨教师加入课程。教师创建的学生初始由创建教师唯一管理；成功加入其他教师课程后，账号永久降为共享账号，创建教师失去编辑、重置密码、禁用和删除权限。学生在同一课程最多属于一个组，也可以只加入课程而不分组。

## 核心设计

```text
管理员发布不可变模板版本
          ↓
教师选择模板与参数 → 校验授权和配额 → Environment + Job
                                                ↓
                                   Step + Operation（原子建立）
                                                ↓
                                  插件运行时 → 外部基础设施
                                                ↓
                             结果、检查点和已知外部引用持久化
                                                ↓
                          平台按模板生成实验资源及其动作绑定
                                                ↓
                       教师分配 → 学生通过环境/资源动作入口使用
```

- **按需模板工作流**：以明确请求驱动创建、动作和 cleanup；周期扫描恢复执行事实，不持续 Reconcile 或自动修复外部漂移。历史 control-plane v0.2 不再是实施基线，见[架构 ADR-001](docs/architecture.md#11-adr-001采用按需模板工作流不以持续协调为-v1-基线)。
- **单体控制平面**：API、执行器、恢复扫描和会话服务在同一进程内模块化运行；不拆分 Web/Worker/Monitor 部署。不合作插件可能耗尽真实线程容量，此时降级、停止受影响派发并等待管理员人工重启，不自动补线程或自动重启。
- **PostgreSQL 持久化**：保存对象、Job/Step/Operation、配额、凭据、会话元数据及审计；进程内线程池只承担执行，不是事实来源。
- **启动加载插件**：从可信插件目录扫描，按部署配置的 required/optional 处理加载失败。v1 不做热更新、在线安装或多版本共存。
- **插件自治**：Manifest 是技术能力的权威来源，核心不维护供应商动作白名单或危险命令过滤器；管理员可以发布 SSH 命令模板。
- **模板是业务入口**：教师、学生不能绕过模板构造插件调用；动作、参数及后端授权由模板快照和业务关系共同决定。
- **平台创建资源**：插件返回结果，不向平台注册实验资源。平台根据模板生成资源及其操作绑定，不为 VM、VLAN 等类型建专用表。
- **插件私有存储**：平台提供隔离、版本化的 Storage API，插件解释内部 JSON。SSH 主机清单不自动纳管、不强制绑定或独占分配。Job 固定实例配置、Storage 列表快照和秘密版本映射，后继步骤不静默读 latest；普通轮换可保留仍有效的旧版本，紧急吊销阻断交付。
- **失败保留现场**：默认不自动逆序补偿；显式运行模板清理流程。未知外部结果不盲目重发，未确认清理不提前释放配额。
- **通用交互会话**：终端流独立于普通 JSON 操作结果；WebSSH、旁观、接管和断连使用独立会话协议。

首版以通用平台、插件接入规范和 SSH 命令执行插件验证闭环，不以 PVE、OpenWrt 或 Kubernetes 插件全部完成为前提。SSH 用于执行模板操作的管理主机，不自动成为学生终端入口或实验产出。

## 设计规范索引

| 文档 | 内容 |
| --- | --- |
| [架构与产品边界](docs/architecture.md) | 领域对象、职责、角色、单体部署、已确认范围及非目标 |
| [插件接口规范](docs/plugin-contract.md) | Manifest、prepare/execute/poll/cancel、Storage、凭据、交互会话 |
| [模板与资源动作规范](docs/template-resource-contract.md) | 参数、选择器、有界展开、资源生成、动作绑定、清理及状态显示 |
| [执行与持久化规范](docs/execution-persistence-contract.md) | PostgreSQL 队列、原子性、Operation、部分引用、阻断互斥、恢复和配额 |
| [身份、授权与安全规范](docs/identity-security-contract.md) | 学生唯一管理、课程分组、环境分配、密码展示、WebSSH 撤权和审计 |

规范使用“必须/禁止”表示目标实现的验收约束，“建议”表示可调整实现选择。示例各自说明适用的契约形状。实现入口和实测范围见本 README 与对应验收记录，详细字段以各专题规范为准。

## 当前代码位置

| 路径 | 当前实现 |
| --- | --- |
| `control_plane/cli.py` / `control_plane/runtime.py` | CLI、启动、协调与关闭 |
| `control_plane/execution/` / `control_plane/plugins/` | 持久化执行、恢复和插件运行时 |
| `control_plane/templates.py` / `control_plane/business.py` | 实验环境模板、准入与工作流 |
| `control_plane/web/` | Starlette HTTP、浏览器界面和 WebSocket 适配 |
| `plugins/` | SSH 管理命令与环境 SSH PTY 插件 |
| `migrations/` | PostgreSQL Alembic 迁移 |
| `tests_control_plane/` | 严格测试套件和 Chromium 验收 |

## 安装与数据库初始化

```sh
python -m pip install -r requirements.txt
```

控制面使用专用 PostgreSQL 数据库。应用表和 Alembic 版本表位于 `control_plane` schema，迁移发现无关用户表时会拒绝执行。

```sh
# 管理会话：CONTROL_PLANE_DATABASE_URL 指向专用库的迁移账号。
# 运行角色由部署管理员预先创建，登录秘密通过受控渠道设置，不写入仓库。
python -m control_plane db upgrade
python -m control_plane db grant-runtime control_plane_runtime

# 结束管理会话。使用独立低权运行账号的 URL 启动，不向运行进程注入迁移凭据。
python -m control_plane start
```

- `db upgrade [head]` 显式执行 Alembic 迁移。DDL 与版本写入在同一事务；并发迁移或正在运行的协调者占锁时拒绝迁移。
- `start` 只校验 schema revision、必需表与有效数据库权限，不执行 DDL。空库、不兼容版本或不安全/不完整权限退出 4，并给出脱敏提示。当前 head 为 `0004_p3_business_services`。从 P2 升级时，先停止协调者，再运行上面的升级和授权命令，为既有运行角色补齐新表权限。
- `db grant-runtime ROLE` 在与迁移相同的事务/互斥/专用库守卫下向已有角色授予固定最小权限；不创建角色、存储密码或静默撤销 PUBLIC/其他角色权限。危险权限必须由部署管理员先纠正。运行进程必须直接用独立低权登录角色连接，拒绝高权会话 `SET ROLE` 伪装；运行账号不能是 superuser、owner、可提权成员或具有持久 DDL/TRUNCATE 权限的角色。
- 运行账号对追加历史、审计、执行证据、日志只拥有 SELECT/INSERT；对 Alembic 版本表只 SELECT，对协调租约只 SELECT/UPDATE，其余应用表按固定策略授权。不授予 DELETE/TRUNCATE/TRIGGER/REFERENCES/MAINTAIN；数据库角色权限与语句级 TRUNCATE 保护共同守住证据，迁移账号不交给普通运行进程。数据库超级用户/部署管理员仍是可信管理边界，不承诺阻止其显式 DDL。
- 协调者持有专用连接的 advisory lock 及持久 owner/revision/期限；续期核对数据库时间和实际锁归属。取得、续租、释放仍使用数据库端 lock/statement timeout（每语句最多 1 秒且不超过租期的四分之一）。本实例合法 UoW 持有租约行期间，心跳只做非锁定数据库资格校验、不更新租期，避免与自身写事务争锁；忙时留下的续租请求在下一笔 UoW 开始前或空闲心跳取得本地写门后执行，不能在同一长事务内无限续活。门覆盖实际提交/回滚；本地门和待续租标志只是同步机制，不是协调资格或恢复事实。数据库确认失锁/过期、外部未知行锁超时或资格校验失败仍退出 4，不自动重取。核心写事务必须在现有租约有效期内完成，不能跨越外部 I/O。
- 权威写入通过 `fenced_transaction()` 获取同线程、同事务的受控 Unit of Work；`write_storage()` / `admit_job()` 拒绝裸连接、过期/跨线程/已退出对象，入口和提交前核对数据库资格；这些检查发现失权时整体回滚。stop 撤销新的和排队中的旧世代写入，不等待本地写门；已通过终检并发出 COMMIT 的事务不能承诺被撤回，必须按数据库实际提交事实处理。不暴露提前 commit/rollback 的连接或结果句柄，事务控制不属于 UoW 接口。此边界防止可信核心的误用，不是恶意 Python 代码沙箱，也不能终止远端命令。
- `CONTROL_PLANE_LEASE_SECONDS` 默认 30 秒，范围 1～3600；必须大于两次 `CONTROL_PLANE_LOCK_POLL_SECONDS` 加一次连接预算。连接预算默认 5 秒、轮询默认 1 秒。
- `db downgrade base` 只允许应用表为空；存在业务/执行/审计数据时拒绝降级。它不是旧库迁移、外部资源清理或生产回退方案。
- 领域表覆盖身份、课程、配额、插件配置/Storage 历史、模板、环境、执行、冲突、秘密、会话与审计；包含唯一约束、跨作用域外键、JSON 上限与不可变历史保护。Storage head 身份不可更改，不可删除重建或指向旧历史；延迟约束要求提交时指向最新历史，墓碑后也必须精确 CAS 前进。增量迁移发现旧 head 回退或有历史无 head 时整体回滚，不自动修复故障证据。底层请求去重和 Storage CAS 已实现；Storage API、执行器及业务授权见下文。

## 新控制面 P2 插件运行时与持久执行内核

P2 向 P3 提供插件能力、持久化执行、恢复与结果应用接口。业务模板、实时授权和配额处置由 P3 服务实现。

- **插件加载**：启动时从部署配置指定的可信目录扫描，`manifest.yaml`（JSON Schema 2020-12，本地引用）与包内代码摘要一并固定；required 失败阻止启动，optional 失败标记不可用且不删数据；不热更新、不联网取 Schema、不从数据库加载可执行路径。样例 `plugins/ssh/` 为可部署包（摘要覆盖真实 provider 源码）。
- **唯一 SecretService**：AES-256-GCM，部署 keyring 无默认密钥；AAD 绑定秘密身份/版本/用途/环境；授权链为“管理员配置显式允许集合 → Job 固定版本映射 → `(job, instance, exact_version)` grant → PreparedCall 实际引用子集 → Handle”，插件自报引用或 Storage 中出现引用本身不产生权限；吊销/失效即时阻断，不回退旧版本也不换 latest。
- **Storage**：实例绑定、Job as-of 快照、稳定分页游标、精确 CAS 与墓碑；写成功不刷新原 Job 视图；只有受控成功输出或 `trusted_for_derivation` 检查点可显式派生更晚版本。
- **执行内核**：PostgreSQL 是事实来源。短事务 `FOR UPDATE SKIP LOCKED` 领取并校验 coordinator fence、Job token/期限与执行组 revision；prepare 在事务外且预算固定一次；Step→running 与 prepared Operation 同事务；派发意图与不可变 `operation_call_attempts` 先提交再调用插件；外部调用不持有事务。
- **结果与恢复**：安全原结果先追加为证据，再在同一事务内应用输出/资源/本地生成项/生命周期；映射失败保留现场并 blocked。晚到结果只能由当前有效协调者按原 call 来源追加证据，不能改权威状态、释放配额或解锁；未知变更不重发，`keyed/read_only` 重试也被原 Operation deadline 与次数限制。
- **有界容量与降级**：普通/控制/会话分道限额，超期调用继续占真实 slot，不补线程；饱和时停止受影响派发、拒绝新准入并显示 degraded，等待人工重启。
- **会话协议**：与 execute JSON 结果分离的独立帧协议，单输入控制者（CAS + epoch）、旁观只读、接管审计、旧世代输入丢弃、有界缓冲与限速、撤权/停止立即 fail-closed，重启标记 disconnected 而非 failed。
- **准入边界**：`AdmissionController` 在单一受控事务内做实时授权、请求幂等、有限持久队列与容量检查；缺少 P3 `AdmissionPolicy` 时默认拒绝，绝不使用成功 no-op 策略。

启用 P2 服务需要显式部署配置（`CONTROL_PLANE_RUNTIME_CONFIG`）、插件目录与加密 keyring 环境变量；缺少其中任一项时基础模式不构造秘密服务、不启用执行，也不生成默认密钥。真实连接配置、密钥与凭据密文不得提交到仓库。

## P3 服务层入口

显式配置部署并启动控制面后，`PluginServices` 提供以下业务服务。Python 服务调用的 `actor_id` 由可信调用方提供。HTTP 适配器从已认证会话读取该身份。

| 服务 | 用途 |
| --- | --- |
| `templates` | 管理员保存草稿、校验插件能力与引用、发布不可变版本、停用版本 |
| `business` | `list_candidates` 查询已发布模板的候选项，`set_quota` 设置教师额度，`create_environment`、`run_action` 和 `cleanup` 返回 Job ID 与是否幂等重放 |
| `identity` | 管理账号、课程与组，授予和撤销同课程的环境分配 |
| `credentials`、`access` | 审计环境凭据查看，跟踪远端撤权，根据已确认的环境凭据解析会话入口 |

部署时，可为已有插件实例设置唯一的 `instance_alias`（如示例中的 `ssh_lab`）。别名一经绑定即固定；已有实例 ID 和历史执行快照继续有效。SSH 包的 Manifest 已更新。旧配置固定了原插件包摘要，升级包前须处理仍依赖旧包的未决任务，再为新包创建匹配的新配置版本。

创建或执行动作时，业务层核对实时权限，按发布版本解析参数和只读候选项。候选查询在事务外调用插件；准入时再次比对配置与 Storage 的版本。准入写入的固定快照驱动后续步骤。恢复时从数据库读取已展开的项和已确认的输出。已派发但结果未知时保留现场、冲突保护及配额，显式清理需要核对原操作证据。

可从 [SSH 示例模板](docs/template-resource-contract.md) 和 [服务入口集成测试](tests_control_plane/test_p3_integration.py) 核对一次完整调用。

## P5 HTTP、界面与 WebSSH

沿用专用 PostgreSQL、低权限运行角色、部署插件配置和加密 keyring。空的控制面账号表可使用 `python -m control_plane bootstrap-admin 用户名` 初始化第一位管理员，命令在终端读取并确认密码。

设置 `CONTROL_PLANE_HTTP_ORIGIN` 为浏览器访问的完整 origin，例如 `https://lab.example.com`，再运行 `python -m control_plane start`。HTTP、WebSocket、执行器和恢复扫描同进程启动。监听地址为回环，`CONTROL_PLANE_HTTP_PORT` 默认 8000。部署代理负责 HTTPS，并保留公开的 `Host`、`Origin` 和 WebSocket Upgrade。配置一个同源地址，路径、通配符和尾斜杠均不属于 origin。省略 HTTP origin 时可启动仅服务层的控制面。

浏览器会话使用 HttpOnly、SameSite=Strict Cookie，HTTPS origin 启用 Secure。会话在控制面重启时失效。修改请求要求精确 Origin、JSON 和 `X-CSRF-Token`，其中登录前的 token 来自 `GET /api/session`。环境创建、动作、清理及终端建立返回 202 和 Job 状态地址，冲突返回 409，容量拒绝返回 503。Job 日志公开平台执行事件代码和时间。

`plugins/ssh_terminal/` 提供独立的环境 SSH 会话能力。发布模板时在 `access` 指定该实例、允许角色、已确认目标和环境凭据引用。该 SSH 能力使用目标 IP、端口、用户名及固定 host key，并验证远端 host key 后使用已确认版本的环境密码进行认证。终端建立固定插件配置、连接目标和凭据版本。环境的创建流程负责设置并确认远端凭据。教师旁观或接管属于自己管理的环境。平台通道状态与远端撤权结果分别展示。

## 当前测试与验证

2026-11-20 P5 实测通过严格控制面套件 442 项，0 跳过。Chrome 完成发布、创建与分配、学生操作、回环 WebSSH、教师接管及显式清理。环境与复现步骤见 [P5 验收记录](tests_control_plane/browser/P5_ACCEPTANCE.md)。

2026-11-18 P3 实测使用 Python 3.12、一次性 PostgreSQL 17 和回环 SSH，运行 `python -B scripts/run_ci_tests.py`。416 项通过，0 跳过。套件覆盖最小权限升级、模板发布、配额并发、授权撤销、持久展开、清理证据和凭据轮换。P5 实测见独立的浏览器验收记录。

严格测试入口（Linux/WSL）：

```sh
bash scripts/run_p1_tests.sh
```

脚本默认在项目 `tmp/p1-venv` 安装运行依赖和测试所需的 HTTPX，使用本地 Podman 或 Docker 创建仅回环开放、密码认证的一次性 PostgreSQL 17，退出时清理自身容器。CI 发现 `tests_control_plane/` 中的测试，遇到跳过、零测试、未运行完或失败都会退出报错。

P0 原始冻结文件及通过记录对应 `352437b`；P1 对空库拒启和显式迁移的演进见 `tests_control_plane/P0_ACCEPTANCE.md`，不重写历史冻结哈希。

2026-11-11 历史实测：P1 初始版本在默认 WSL、Python 3.12.13、Podman 一次性 PostgreSQL 17 执行 `bash scripts/run_p1_tests.sh`，103 项全部通过，0 失败、0 错误、0 跳过。

2026-11-14 审查修复实测：默认 WSL `RHEL-10.2`、项目隔离 Python 3.12 环境、Podman 一次性 PostgreSQL 17，执行同一严格入口，147 项全部通过，0 失败、0 错误、0 跳过（54.364 秒）。覆盖原有显式/原生 Alembic 升降级与故障矩阵，新增心跳长持锁/信号有界退出、失权 API 拒绝与整事务回滚、跨线程/退出后 UoW 拒绝、提前提交句柄隔离、真实低权运行账号正常提交及 TRUNCATE/DDL 拒绝、PUBLIC/继承/SET ROLE/列级提权拒启、Storage head 回退/孤立历史/并发/旧异常库升级回滚，以及 pg8000 pre_ping 连接池反复复用。最初回归暴露的 OID 角色重载和预检隐式事务已定位修复，最终严格全套通过；测试容器由脚本退出清理。未运行旧 Flask 套件、真实设备、生产迁移或浏览器端到端验证；本地通过不代替当前提交的 GitHub 托管 CI 或人工复审。


2026-11-14 二轮复审实测：针对合法 UoW 与心跳自竞争，在旧 `bc32ee3` 源码上以新增确定性低权回归复现 `LeadershipLost`；同一回归在修复后通过。默认 WSL、隔离 Python 3.12、一次性 PostgreSQL 17 执行严格入口，158 项全部通过（63.820 秒），0 失败、0 错误、0 跳过。新增 11 项覆盖慢写与多次 poll、忙时不续租、单笔过期/失锁回滚、连续短写事务边界续租、真实提交与异常回滚期间的门、排队写世代/重入拒绝、专用连接串行及 stop/续租计数交错；原有 147 项与迁移未改动。未运行旧 Flask、真实供应商、生产库或浏览器验证；托管 CI 和人工复审另行核实。

2026-11-15 P2 实测：默认 WSL `RHEL-10.2`、项目隔离 Python 3.12、Podman 一次性 PostgreSQL 17，同一严格入口执行 `bash scripts/run_p1_tests.sh`，352 项全部通过，0 失败、0 错误、0 跳过（107.645 秒），测试容器由脚本退出清理。新增 P2 覆盖：迁移增量与旧 P1 数据升级前置拒绝、执行状态图与终态保护、claim/heartbeat/token/组 revision 双重 fencing、prepare 原子性与预算不刷新、派发意图与 call 来源先提交、同步/晚到证据去重与 `trusted_for_derivation` 边界、结果原子应用与本地重放、两恢复者 CAS、取消与真实成功竞态、未知/超时不重发、容量超期不返 slot 与饱和拒新、会话单控制者/接管/背压/撤权重启语义、Storage 快照与 CAS、Secrets 的实例级授权/轮换/吊销/派生幂等、准入同事务去重与回滚，以及最小 SSH 插件对隔离回环 Paramiko 服务的真实握手、严格 host key、命令与预算验证。

P2 首轮的 10 个失败同源于受控 Unit of Work 结果缺少 `.mappings()`。补齐只读映射包装后通过全套断言。该历史结果的范围为 P2。

新旧部署按[架构中的退役前置条件](docs/architecture.md#91-旧部署退役与硬切换前置条件)硬切换：先确认旧外部对象、未决任务、责任人和管理通道，验证旧库、凭据密文及独立密钥的备份恢复路径；新旧系统不得无协调同时修改同一对象。不要求自动迁移或兼容，不等于授权销毁真实资源、旧库、唯一管理凭据或故障证据。

真实连接配置、会话密钥、凭据密文与加密密钥均不可提交到仓库。
