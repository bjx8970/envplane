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

通过 `CONTROL_PLANE_TEST_VENV=/tmp/k8s-p5-venv bash scripts/run_p1_tests.sh` 使用本地 Docker 创建并清理回环 PostgreSQL 17。最终严格套件 442 项全部通过，0 失败、0 错误、0 跳过，用时 171.876 秒。HTTP 回归覆盖 HTTPS 配置下的 Cookie 属性、CSRF、精确 Origin、401/403、202、幂等重放及 409、503、安全错误和 Job 归属。实时回归覆盖异源握手、非所属教师、只读旁观、接管与释放、帧和缓冲约束、撤权及重启断连。

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

浏览器使用 HTTP/WS 回环地址。HTTPS Secure Cookie 在 HTTPS 基址的 HTTP 契约测试中检查，生产 TLS 代理链路未实测。远端撤权在浏览器中覆盖缺少远端能力的处置路径。测试服务运行合成回显，没有验证真实设备上的命令、外部直连终止或生产迁移。旧 Flask 套件及托管 CI 不在本次本地执行范围内。
