# Issue #28 P5 验收记录

2026-11-20，分支 `codex/p5-http-ui-webssh` 从当日 `origin/main` 的 P3 合并提交 `0b0f61c8ce926310019cbd6d9dce95fae265b84d` 创建。

## 已实测的浏览器闭环

在 Debian 13 WSL 2、Python 3.13.5、一次性 PostgreSQL 17 和 Windows Chrome 157.0.8103.79 中使用 Playwright Core 1.60.0 执行 [浏览器验收脚本](p5_acceptance.cjs)。HTTP 和 WebSocket 使用同一个本地 origin。测试插件设置临时环境密码，以独立 SSH 终端插件完成实际 SSH 握手、固定 host key 验证、环境密码认证、PTY、resize 和双向字节传输。回环 Paramiko 服务将输入回显。

| 步骤 | 实测结果 |
| --- | --- |
| 管理员登录、创建插件实例、保存并发布模板 | 发布成功，教师可以选择发布版本 |
| 教师创建课程及小组、加入学生并分组、依据候选项和模板字段创建环境、按组分配 | Job 成功，环境就绪，分配生效 |
| 学生使用资源动作并查看凭据 | 资源状态由 unknown 变为 online，页面显示观测时间。凭据独立授权，响应包含 `Cache-Control: no-store` |
| 学生连接 WebSSH，教师旁观、接管并释放 | Chrome WebSocket 收到真实 SSH PTY 回显。教师接管时学生只读，释放后恢复输入 |
| 教师撤销分配，再显式清理 | 学生通道断开，教师页面显示平台 `disconnected`。远端撤权另列 `revocation_failed / unsupported`。清理 Job 成功，环境显示 `deleted` |

## 独立启动实测

在另一个一次性数据库中运行 CLI 初始化管理员，再通过 `python -m control_plane start` 启动 HTTP。就绪接口返回 ready，管理员登录成功，SIGTERM 后进程正常退出。

## 严格控制面套件

通过 `CONTROL_PLANE_TEST_VENV=/tmp/k8s-p5-venv bash scripts/run_p1_tests.sh` 使用本地 Docker 创建并清理回环 PostgreSQL 17。P5 初版 `43d1e0b` 的严格套件 442 项全部通过，0 失败、0 错误、0 跳过，用时 171.876 秒。HTTP 回归覆盖 HTTPS 配置下的 Cookie 属性、CSRF、精确 Origin、401/403、202、幂等重放及 409、503、安全错误和 Job 归属。实时回归覆盖异源握手、非所属教师、只读旁观、接管与释放、帧和缓冲约束、撤权及重启断连。

## PR #34 审查修复

新增两项 PostgreSQL 回归。控制池排队超时将未派发的 Step 和 Job 持久化为失败并释放执行冲突保护，下一次会话仍可打开。两个环境争用最后一个接收槽位时，测试观察到 PostgreSQL 事务锁等待，并验证只有一个 Job 入队。

同一浏览器脚本已在回环 SSH 和 Windows Chrome 上重新通过。GitHub Actions 新增独立的 `browser-e2e` job，在一次性 PostgreSQL 17 中使用 Playwright 和无头 Chromium 运行该脚本。

## 复现浏览器验收

在项目根目录启动一次性夹具，保留服务终端运行。

```sh
bash scripts/run_p1_tests.sh --browser-fixture
```

在另一终端安装 Playwright Core 并运行脚本。将 Chromium 可执行文件路径作为第三个参数。Windows Node 与 Chrome 从 WSL 调用时，使用 `wslpath -w` 转换脚本、夹具和 Node 模块路径。

```sh
npm install --prefix tmp/p5-browser playwright-core@1.60.0 --no-audit --no-fund
node tests_control_plane/browser/p5_acceptance.cjs \
  http://localhost:18742 ./tmp/p5-browser-fixture.json /path/to/chromium \
  "$PWD/tmp/p5-browser/node_modules/playwright-core"
```

结束服务终端后脚本清理本次 PostgreSQL 容器。所有夹具用户和凭据均用完即弃。

## 实测范围边界

P5 初版浏览器使用 HTTP/WS 回环地址，并通过 HTTPS 基址的 HTTP 契约测试检查 Secure Cookie。远端撤权在浏览器中覆盖缺少远端能力的处置路径。原 P5 验收范围为合成回显和一次性 PostgreSQL。

## 管理员运维与隔离发布演练

2026-11-23 在 Debian 13、Python 3.13、PostgreSQL 17.12、Playwright 1.60 和无头 Chromium 148.0.7778.96 上验证。现有浏览器脚本以回环 TLS 代理转发 HTTP 和 WebSocket，浏览器使用本次临时证书。通过 readiness、精确 Origin 和 Secure、HttpOnly、SameSite=Strict Cookie 检查。管理员查看容量、打开阻断 Job、选择核对结论并查询原调用。运维入口仅向管理员显示。原有发布、分配、学生动作、凭据、WebSSH 回显、接管、撤权和显式清理全部通过。

使用一次性 PostgreSQL 17.12 和隔离 Python 环境运行严格入口 `python -B scripts/run_ci_tests.py`，453 项全部通过，0 跳过，用时 154.264 秒。测试对应关系见[执行故障窗口](../../docs/execution-persistence-contract.md#12-验收故障窗口)。

| 发布检查 | 演练结果 |
| --- | --- |
| 新库版本与授权 | 在一次性专用库显式升级到 `0004_p3_business_services`，再升级到 `0005_admin_recovery`，重复升级成功。浏览器夹具使用独立低权限运行角色启动。 |
| 停止旧变更入口 | 从 `main` 的隔离源码副本启动旧应用并验证回环入口。停止旧进程后确认入口关闭，合成对象、责任人及未决结果仍可从旧库核对。 |
| 备份与回退 | 使用 `pg_dump` 备份合成记录及凭据密文，单独保管测试密钥。停止新控制面和 TLS 代理后恢复到另一空库，使用独立密钥解密验证，并从恢复库重新启动旧应用。 |

正式切换前由部署负责人核实真实对象和远端未决调用、逐项确认接管责任与管理路径、验证生产备份和密钥恢复，再确认生产代理与维护窗口。任一项未确认时暂停切换；回退前先停新变更入口并复核接管对象的执行事实。
