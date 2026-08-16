# dsh-login-gateway

DeepSeek Harness（dsh）的**登录门卫插件**。dsh 的 Web UI 默认只监听 `127.0.0.1:3080`，禁止外部访问；本插件在外部再开一个入口（默认 `0.0.0.0:3081`），访问者先通过**用户名密码登录**，登录成功后流量被**全量反向代理**到 dsh 的 Web UI（HTTP 与 WebSocket 都支持），功能零缺失。

零运行时依赖（只用 Node.js 内置模块），Node 22+ ESM。

---

## 它解决什么问题

- 想从局域网/公网访问本机 dsh，但 dsh 只监听 loopback；
- 直接改 dsh 让它监听 `0.0.0.0` 会裸奔在公网上，任何人可访问；
- 本插件：外部入口 + 登录墙 + 反代，dsh 本身保持零侵入（继续只听 127.0.0.1）。

## 工作架构

```
浏览器 ──HTTP/WS──▶ 0.0.0.0:3081（门卫：登录校验 + 会话 Cookie）
                         │ 通过校验后全量反代（改写 Host/Origin/Sec-Fetch-Site 为 loopback 形态）
                         ▼
                    127.0.0.1:3080（dsh Web UI，信任围栏放行，特权 API 全可用）
```

关键点：反代时把请求头里的 `Host`/`Origin`/`Sec-Fetch-Site` 改写为 loopback 形态，让 dsh 把请求当作"本机请求"信任放行；WebSocket 升级请求同样先校验会话再转发。

## 快速开始（首次安装）

1. 把本项目放到 dsh 服务器上（例如 `/data/dsh-login-gateway`），并安装依赖（仅 devDependencies，运行时无依赖）：

   ```bash
   cd /data/dsh-login-gateway
   npm install
   ```

2. 在 dsh 的 profile 配置里挂载插件（编辑 `cordis.patch.yml`，见下节"部署步骤"），重启 dsh。

3. **获取一次性初始化令牌**（二选一）：

   - **a) dsh 启动终端的输出**：插件会直接往进程 stdout 打印一行（不走日志服务，dsh 启动的终端里就能看到）：

     ```
     [login-gateway] 登录门卫未初始化，请访问 http://<主机>:3081/setup 并输入一次性令牌：ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456
     ```

   - **b) 读取令牌文件**：令牌同时写在用户文件同目录下的 `setup-token.txt`（权限 0600，内容仅令牌本身）：

     ```bash
     cat ~/.dsh-login-gateway/setup-token.txt
     ```

4. 浏览器打开 `http://<主机>:3081/setup`，输入令牌、管理员用户名、密码（至少 8 位）与确认密码，点击"完成设置"。

5. 跳转到登录页，用刚创建的账号登录，即可进入 dsh。

> 说明：令牌只在**未初始化**时生成；初始化完成后 `/setup` 会返回 410，`setup-token.txt` 也会被自动删除。

## 配置项

所有配置都有缺省值，只有 `users`（可选）需要在确实要"从配置写死初始账号"时才填写。完整配置表：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `listenHost` | `0.0.0.0` | 门卫监听地址，暴露给外部 |
| `listenPort` | `3081` | 门卫监听端口 |
| `targetHost` | `127.0.0.1` | dsh Web UI 监听地址 |
| `targetPort` | `3080` | dsh Web UI 监听端口 |
| `sessionTtlHours` | `24` | 登录会话有效期（小时） |
| `maxLoginAttempts` | `5` | 同一 IP 连续失败多少次后锁定 |
| `lockMinutes` | `5` | 锁定持续分钟数 |
| `setupMaxAttempts` | `5` | `/setup` 初始化：同一 IP 连续失败多少次后锁定 |
| `setupLockMinutes` | `30` | `/setup` 初始化锁定持续分钟数 |
| `proxyTimeoutMs` | `60000` | 反代上游响应头等待超时（毫秒），超时返回 504；WS 握手超时取与 15s 的较小值 |
| `streamIdleTimeoutMs` | `1800000` | 反代响应流空闲超时（毫秒，默认 30 分钟）：响应头到达后 SSE 等长思考间隙不被 60s 请求超时打断，仅长时间无数据才断开 |
| `maxConnections` | `512` | HTTP 服务最大并发连接数，超出后新连接被丢弃 |
| `userStorePath` | `~/.dsh-login-gateway/users.json` | 用户数据文件路径（可自定义） |
| `users` | 无（可选） | 种子用户数组 `[{ username, passwordHash }]`，仅当用户文件不存在时写入并采用 |

### `users` 种子配置（可选，向后兼容）

首次安装不想走 `/setup` 引导的话，可以直接在配置里写死初始账号：

```yaml
config:
  users:
    - username: admin
      passwordHash: 'scrypt$16384$8$1$...'   # 用下面的工具生成
```

生成哈希：

```bash
npx dsh-login-gateway-hash "你的密码"
# 或直接运行
node bin/hash.js "你的密码"
```

> 种子只在**用户文件不存在**时写入文件并采用。一旦 `/setup` 创建过账号或文件已存在，改 `users` 配置不再生效——请直接编辑 `users.json` 文件。

## 部署步骤（cordis.patch.yml）

在 dsh 的 profile 目录（如 `/root/.dsh/profiles/web/`）的 `cordis.patch.yml` 中追加挂载项：

```yaml
- insert:
    - id: login-gateway
      name: '/data/dsh-login-gateway/src/index.js'
      config:
        listenHost: '0.0.0.0'
        listenPort: 3081
        targetHost: '127.0.0.1'
        targetPort: 3080
        sessionTtlHours: 24
        maxLoginAttempts: 5
        lockMinutes: 5
        # 首次安装可不配 users，改用 /setup 引导创建管理员账号
        # users:
        #   - username: admin
        #     passwordHash: 'scrypt$16384$8$1$...'
```

保存后重启 dsh，或使用 dsh 的热重载功能。

## 使用说明

- **登录**：打开 `http://<主机>:3081/`，输入用户名密码。成功后会种下会话 Cookie（`dsh_gw_session`，HttpOnly + SameSite=Strict），之后访问全部走反代，包括 WebSocket。
- **登出**：`POST /logout`（页面无入口时为 `curl -X POST http://<主机>:3081/logout`），会清除会话并跳回登录页。
- **未登录访问**：`/` 返回登录页；其余路径返回 `401` JSON。
- **限速**：同一 IP 连续输错 `maxLoginAttempts` 次会被锁定 `lockMinutes` 分钟，期间该 IP 登录一律 401 并提示锁定。
- **账号锁定**：同一**用户名**跨 IP 累计失败 `maxLoginAttempts` 次也会被锁定——代理池分布式攻击（每 IP 只试几次）也会触发，锁定期间任何 IP 用该用户名登录都拒绝并提示"该账号已被临时锁定"；IP 与用户名两个维度独立计数、任一锁定即拒绝。
- **初始化限速**：`/setup` 同样按 IP 限速——令牌错误、用户名空、密码过短、两次密码不一致均计失败，连续失败 `setupMaxAttempts` 次锁定 `setupLockMinutes` 分钟，期间一律返回 429。

## 安全说明

- **务必走 HTTPS**：门卫本身只做 HTTP 登录 + 反代，公网直接暴露明文账号密码与流量有风险。建议在前面挂 Nginx/Caddy/云负载均衡做 TLS 终止（例如 443 → 127.0.0.1:3081）。
- **会话 Cookie** 使用 `HttpOnly` + `SameSite=Strict`，页面无 XSS 注入点。
- **一次性令牌**为 32 位随机十六进制（连字符分组展示，128 bit 熵），只在未初始化时有效，初始化后即失效；`setup-token.txt`（0600）只含令牌本身，初始化完成后自动删除。
- **用户文件**默认在 `~/.dsh-login-gateway/users.json`，内含 scrypt 哈希（不可逆）。写入时自动使用 0600 权限、目录自动 0700，无需手工 `chmod`。
- **登录/初始化限速**按来源 IP 与用户名双维度独立计算：初始化入口 `/setup` 在未初始化阶段暴露（默认 `0.0.0.0`），连续失败会被锁定并返回 429，防止分布式暴力猜测令牌抢占管理员账号；登录失败记录带 TTL（30 分钟未命中自动清理），防止内存膨胀。
- **反代超时**：上游 dsh 响应头等待超 `proxyTimeoutMs`（默认 60s）返回 504，WS 握手超时不超过 15s；响应头到达后改用 `streamIdleTimeoutMs`（默认 30 分钟）空闲超时——AI 流式输出（SSE）的长思考间隙（>60s）不会被打断；502/504 响应体为固定文案（`bad gateway`/`gateway timeout`），不泄漏内部错误信息。
- **并发连接上限**：`maxConnections`（默认 512）限制最大并发连接数；`headersTimeout` 15s、`requestTimeout` 30s、`keepAliveTimeout` 5s 显式收紧（Node 默认 60s），防 slowloris 慢速攻击与连接堆积耗尽资源。
- **安全响应头**：门卫自己生成的响应（登录页/引导页/JSON/302/401/410/429/405/500）统一带 `X-Frame-Options: DENY`（防 iframe 点击劫持/钓鱼）、`Referrer-Policy: no-referrer`、`Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'`（登录页/引导页为内联样式+内联脚本）。反代透传的 dsh 响应**不加**这些头，保持原样。
- 登录/初始化接口有请求体大小上限（100KB），防止恶意超大请求。

## 重置与常见问题

- **重置管理员账号**：删除用户文件后重启 dsh，会再次进入"未初始化"状态，重新打印一次性令牌，走 `/setup` 重新创建：

  ```bash
  rm -f ~/.dsh-login-gateway/users.json
  ```

- **忘记/没看到一次性令牌**：两种获取方式——a) 看 dsh 启动终端的 stdout 输出里 `[login-gateway] 登录门卫未初始化...` 那一行；b) 读取令牌文件：`cat ~/.dsh-login-gateway/setup-token.txt`。若两者都没有（例如服务已运行多时、文件被删），删掉用户文件重启 dsh 会重新生成令牌（见上）。
- **`/setup` 返回 410**：说明已初始化完成，设置入口已关闭，属正常现象。如需重新初始化，先删用户文件重启。
- **访问 `http://<主机>:3081/` 打不开**：检查 dsh 是否已启动、插件挂载是否生效（看日志是否打印"外部入口已启动"）、端口是否被防火墙拦截。
- **登录后页面/接口 502**：门卫反代目标 `127.0.0.1:3080` 不可达，确认 dsh 的 Web UI 进程在运行。
- **用户文件损坏**：启动会直接报错并给出文件路径（不会静默重置）。按上面的"重置方法"处理。

## 技术实现

- 认证：`node:crypto` scrypt（`scrypt$N$r$p$salt$hash` 自描述格式），恒定时间比较防时序攻击。
- 会话：内存 `Map` + 过期清理（30 分钟定时 sweep）。
- 反代：流式透传（SSE 长连接友好），剔除 hop-by-hop 头，WebSocket 升级用后端 `rawHeaders` 原样构造 101 响应。
- 零运行时依赖，所有依赖仅存在于开发/测试环境。

## 目录结构

```
src/
  index.js        插件主入口：配置校验、路由分发、setup 引导、HTTP 服务 + WS 升级
  auth.js         密码哈希（scrypt）、会话存储、登录限速
  proxy.js        HTTP 反代（头改写 + hop-by-hop 剔除）与 WebSocket 升级转发
  user-store.js   用户文件存储（JSON + 原子写入）
  login-page.js   登录页 HTML（深色主题，单文件内联）
  setup-page.js   首次启动引导页 HTML（深色主题，单文件内联）
bin/
  hash.js         密码哈希生成 CLI
```
