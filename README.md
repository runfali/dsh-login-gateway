# dsh-login-gateway

DeepSeek Harness（dsh）的**登录门卫插件**。dsh 的 Web UI 默认只监听 `127.0.0.1:3080`，禁止外部访问；本插件在外部再开一个入口（默认 `0.0.0.0:3081`），访问者先通过**用户名密码登录**，登录成功后流量被**全量反向代理**到 dsh 的 Web UI（HTTP 与 WebSocket 都支持），功能零缺失。

零运行时依赖（只用 Node.js 内置模块），Node 22+ ESM。

---

## 它解决什么问题

- 想从局域网/公网访问本机 dsh，但 dsh 只监听 loopback；
- 直接改 dsh 让它监听 `0.0.0.0` 会裸奔在公网上，任何人可访问；
- 本插件提供：外部入口 + 登录墙 + 全量反代，dsh 本身继续只听 `127.0.0.1`。

## 效果预览

首次访问未初始化时，会进入 `/setup` 引导页，输入一次性令牌并创建管理员账号：

![首次访问初始化页面](img/%E9%A6%96%E6%AC%A1%E8%AE%BF%E9%97%AE.png)

## 工作架构

```
浏览器 ──HTTP/WS──▶ 0.0.0.0:3081（门卫：登录校验 + 会话 Cookie）
                         │ 通过校验后全量反代（改写 Host/Origin/Sec-Fetch-Site 为 loopback 形态）
                         ▼
                    127.0.0.1:3080（dsh Web UI，信任围栏放行，特权 API 全可用）
```

关键点：反代时把请求头里的 `Host`/`Origin`/`Sec-Fetch-Site` 改写为 loopback 形态，让 dsh 把请求当作“本机请求”信任放行；WebSocket 升级请求同样先校验会话再转发。

## 快速开始（首次安装）

1. 用 dsh 标准插件命令安装（本项目是标准 `dsh.bundle` 插件，无需手改 profile 配置）：

   ```bash
   # 本地目录安装（link 形式，profile 直接引用本目录，改源码无需重装）
   dsh plugin --profile web add /path/to/dsh-login-gateway

   # 卸载
   dsh plugin --profile web remove dsh-login-gateway
   ```

   安装/卸载后**重启 dsh** 生效。

2. 获取一次性初始化令牌（二选一）：

   - **方式 A：看 dsh 启动终端或服务日志输出**

     插件会直接输出一行提示，内容类似：

     ```
     [login-gateway] 登录门卫未初始化，请访问 http://<主机>:3081/setup 并输入一次性令牌：ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456
     ```

     日志示例：

     ![初始化令牌日志输出](img/%E6%97%A5%E5%BF%97%E8%BE%93%E5%87%BA.png)

   - **方式 B：读取令牌文件**

     令牌同时会写入用户文件同目录下的 `setup-token.txt`（权限 `0600`，内容只有令牌本身）：

     ```bash
     cat ~/.dsh-login-gateway/setup-token.txt
     ```

3. 浏览器打开 `http://<主机>:3081/setup`，输入令牌、管理员用户名、密码（至少 8 位）与确认密码，点击“完成设置”。

4. 初始化完成后会跳转到登录页，用刚创建的账号登录，即可进入 dsh。

> 说明：新装**没有默认账号**，必须走 `/setup` 引导创建。未初始化时访问 `/` 会自动 `302` 跳转到 `/setup`。令牌只在**未初始化**阶段生成；初始化完成后 `/setup` 会返回 `410`，`setup-token.txt` 也会被自动删除。

## 安装与卸载（标准 bundle 插件）

本项目是标准的 `dsh.bundle` 插件（`package.json` 声明 `dsh.bundle.patch`，随包自带 `cordis.patch.yml` 挂载层），用 dsh 官方插件命令管理，**无需手改 profile 配置**：

### 安装

```bash
dsh plugin --profile web add /path/to/dsh-login-gateway
```

命令会把本目录以 `link:` 形式装进 profile（`~/.dsh/profiles/web/`），并自动把包名追加到 profile 的 `dsh.profile.bundles` 层列表。安装后**重启 dsh** 生效。

> 开发调试提示：`link:` 形式下 profile 直接引用本目录，改源码后重启 dsh 即可生效，无需重装。

### 卸载

```bash
dsh plugin --profile web remove dsh-login-gateway
```

重启 dsh 后，门卫端口 `3081` 停止服务，外部访问恢复为“无法访问”。

可选清理：删除门卫的用户数据目录（账号、令牌文件）：

```bash
rm -rf ~/.dsh-login-gateway/
```

### 个性化配置

随包挂载层只提供默认配置。如需改端口、超时等，在 profile 目录（如 `~/.dsh/profiles/web/`）的 `cordis.patch.yml` 用户层追加覆盖（注意：补丁是**整段替换** `config`，要写全所有项）：

```yaml
- id: login-gateway
  config:
    listenHost: '0.0.0.0'
    listenPort: 3081
    targetHost: '127.0.0.1'
    targetPort: 3080
    sessionTtlHours: 24
    maxLoginAttempts: 5
    lockMinutes: 5
    clientLoopbackTrust: true
    settingsFilePath: '/root/.dsh/settings.yaml'
    settingsFileDownload: true
```

### 是否影响 dsh 本身

**零侵入**。门卫只做三件事：在外部开一个登录入口、校验会话、把通过校验的请求反代到 dsh 的 loopback 端口。它**不修改 dsh 安装目录的任何文件**，也**不改 dsh 自身配置逻辑**；安装/卸载只影响 profile 目录（依赖与 bundles 列表），一条命令即可完全移除。卸载后 dsh 与安装前一致。

## 配置项

所有配置都有默认值，新装默认配置即可工作。完整配置表如下：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `listenHost` | `0.0.0.0` | 门卫监听地址，暴露给外部 |
| `listenPort` | `3081` | 门卫监听端口 |
| `targetHost` | `127.0.0.1` | dsh Web UI 监听地址 |
| `targetPort` | `3080` | dsh Web UI 监听端口 |
| `sessionTtlHours` | `24` | 登录会话有效期（小时） |
| `maxLoginAttempts` | `5` | 同一 IP 连续失败多少次后锁定 |
| `lockMinutes` | `5` | 锁定持续分钟数 |
| `setupMaxAttempts` | `5` | `/setup` 初始化时，同一 IP 连续失败多少次后锁定 |
| `setupLockMinutes` | `30` | `/setup` 初始化锁定持续分钟数 |
| `proxyTimeoutMs` | `60000` | 反代上游响应头等待超时（毫秒），超时返回 `504`；WS 握手超时取与 15s 的较小值 |
| `streamIdleTimeoutMs` | `1800000` | 反代响应流空闲超时（毫秒，默认 30 分钟） |
| `maxConnections` | `512` | HTTP 服务最大并发连接数，超出后新连接被丢弃 |
| `userStorePath` | `~/.dsh-login-gateway/users.json` | 用户数据文件路径（可自定义） |
| `maxSessions` | `1000` | 会话容量上限，超出后逐出最旧会话，防止反复登录刷爆内存 |
| `trustProxy` | `false` | 前置 TLS 反代（nginx/caddy）时设 `true`：从 `X-Forwarded-For` 取真实客户端 IP 参与限速。**直连场景必须保持 `false`**，否则攻击者可伪造该头绕过限速；为 `false` 时门卫会剥离伪造的 XFF/X-Real-IP/Forwarded 头再转发上游 |
| `secureCookie` | `false` | 仅经 HTTPS 访问门卫时设 `true`：会话 Cookie 追加 `Secure` 标记 |
| `clientLoopbackTrust` | `true` | 经门卫访问时，通过随包自带的浏览器端 client bundle（`lib/client.js`）把 dsh 连接标记为 loopback，恢复设置持久化（深色模式、插话发送等），同时保证「设置-模型」「设置-插件-插件配置」正常显示。设 `false` 可关闭（设置将退回不持久化） |
| `settingsFilePath` | `~/.dsh/settings.yaml` | dsh 设置文件路径（供下载路由使用，一般无需改动） |
| `settingsFileDownload` | `true` | 宿主机无桌面环境（容器/无显示器服务器）时，把 dsh 设置页的「打开配置文件」按钮改为从门卫下载该文件（`/__gateway/settings.yaml`）；桌面环境主机自动保持 dsh 原生打开。设 `false` 关闭该兜底 |

## 使用说明

- **登录**：打开 `http://<主机>:3081/`，输入用户名密码。成功后会种下会话 Cookie（`dsh_gw_session`，`HttpOnly` + `SameSite=Strict`），之后访问全部走反代，包括 WebSocket。
- **修改密码**：页面右下角悬浮栏点「改密」，验证当前密码后设置新密码（至少 8 位）。改密成功会**自动下线该账号的其他所有会话**（当前浏览器保持登录），旧凭据即使泄露也随即失效。
- **登出**：悬浮栏「退出」按钮；无界面时可直接调用：`curl -X POST http://<主机>:3081/logout`。
- **未登录访问**：`/` 返回登录页；其余路径返回 `401` JSON。
- **登录限速**：同一 IP 连续输错 `maxLoginAttempts` 次会被锁定 `lockMinutes` 分钟。
- **账号锁定**：同一用户名跨 IP 累计失败 `maxLoginAttempts` 次也会被锁定，可防代理池分布式爆破。
- **初始化限速**：`/setup` 同样按 IP 限速，令牌错误、用户名空、密码过短、两次密码不一致都计失败。
- **审计日志**：登录成功/失败、锁定触发、登出、改密、初始化全程留痕（含来源 IP 与用户名），可在 dsh 日志中检索 `login-gateway` 前缀审计。

## 安全说明

- **务必走 HTTPS**：门卫本身只做 HTTP 登录 + 反代，公网直接暴露会有明文传输风险。建议前置 Nginx/Caddy/云负载均衡做 TLS 终止（例如 `443 -> 127.0.0.1:3081`），此时在门卫配置里同时开启 `trustProxy: true` 与 `secureCookie: true`。
- **会话 Cookie** 使用 `HttpOnly` + `SameSite=Strict`，页面无 XSS 注入点；改密成功自动吊销其他全部会话。
- **一次性令牌**为 32 位随机十六进制（128 bit 熵），恒定时间比较防时序侧信道，只在未初始化时有效；初始化完成后立即失效并删除令牌文件。
- **用户文件**默认在 `~/.dsh-login-gateway/users.json`，内含 scrypt 哈希（不可逆）；写入时自动使用 `0600` 权限、目录自动 `0700`。
- **登录/初始化限速**按来源 IP 与用户名双维度独立计算，失败记录带 TTL，避免内存无限膨胀；限速表与会话表均有容量上限（默认 1 万条 / 1000 个），防伪造海量 IP 或反复登录刷爆内存。
- **反用户名枚举**：登录时账号不存在也会执行等价的 scrypt 计算，成功与失败的响应耗时无差异。
- **反请求走私**：反代剔除全部 hop-by-hop 请求头；`Content-Length` 与 `Transfer-Encoding` 并存的歧义请求两头皆删、由 Node 按实际流重新分块。
- **审计日志**：登录成败、锁定、登出、改密全程留痕（IP+用户名），日志字段净化换行与控制字符防伪造条目。
- **反代超时**：上游响应头等待超 `proxyTimeoutMs` 返回 `504`；响应头到达后改用 `streamIdleTimeoutMs` 空闲超时，SSE 长间隔输出不会被正常打断。
- **并发连接上限**：`maxConnections` 默认 `512`，并显式收紧 `headersTimeout`、`requestTimeout`、`keepAliveTimeout`，减少慢连接占用。
- **安全响应头**：门卫自己生成的响应统一带 `X-Frame-Options: DENY`、`Referrer-Policy: no-referrer` 和 CSP；反代透传的 dsh 响应保持原样。
- 登录/初始化接口有请求体大小上限（`100KB`），防止恶意超大请求。

## 重置与常见问题

- **重置管理员账号**：优先用页面右下角「改密」入口在线轮换（需记得当前密码）。密码彻底遗失时，删除用户文件后重启 dsh，会再次进入“未初始化”状态，并重新打印一次性令牌：

  ```bash
  rm -f ~/.dsh-login-gateway/users.json
  ```

- **忘记或没看到一次性令牌**：可以看 dsh 启动终端/服务日志，或读取 `~/.dsh-login-gateway/setup-token.txt`。如果两者都没有，删掉用户文件并重启 dsh，会重新生成令牌。
- **`/setup` 返回 `410`**：说明已初始化完成，设置入口已关闭，属正常现象。如需重新初始化，先删用户文件再重启。
- **访问 `http://<主机>:3081/` 打不开**：检查 dsh 是否已启动、插件挂载是否生效、端口是否被防火墙拦截。
- **登录后页面或接口 `502`**：门卫反代目标 `127.0.0.1:3080` 不可达，确认 dsh Web UI 进程仍在运行。
- **对话/粘贴时 `/_dsh/vision-toolkit/paste-policy` 等 `/_dsh/` 路由返回 `403`（`origin-rejected`）**：这是上游插件（如 `@anionex/dsh-vision-toolkit`）对请求做的同源校验——没有 `Origin` 时要求 `Sec-Fetch-Site` 为 `same-origin` 等；curl、隐私浏览器等不带浏览器 Fetch Metadata 的客户端会被拒绝。门卫已在反代时把缺失的 `Sec-Fetch-Site` 补齐为 `same-origin`（本修复需重启 dsh 生效），正常浏览器不受影响。
- **用户文件损坏**：启动会直接报错并给出文件路径，不会静默重置。按上面的“重置管理员账号”处理即可。
- **改了设置（深色模式、插话发送等）一刷新就还原**：这是 dsh 的机制限制，不是登录态问题。dsh 把“设置持久化”门控在浏览器地址栏为 loopback（`127.0.0.1`/`localhost`）上；经门卫从外部域名/IP 访问时该判定为否，设置作用域进入内存模式——改动只在当次页面生效，刷新即丢。门卫已通过**随包自带的浏览器端 client bundle**（`lib/client.js`，标准 `dsh.client` 接入，`immediately` 早于 dsh 各设置组件判定生效）把浏览器端连接标记为 loopback，从而恢复持久化（设置会正常写入 `~/.dsh/settings.yaml`）。该机制同时恢复了「设置-模型」「设置-插件-插件配置」（含 dsh 自带插件配置项）的正常显示。若设置 `clientLoopbackTrust: false` 关闭补丁，将退回“设置不持久化”的旧行为。**注意：本修复不修改 dsh 任何源码，改的是门卫插件自带的浏览器端 client bundle；改动需重启 dsh 生效。**
- **设置-打开配置文件提示「无法打开配置文件」**：dsh 的该按钮会在服务器上调用系统级打开（Linux 走 `xdg-open`），无桌面环境（容器、无显示器服务器）上必然失败——这是宿主限制，不是登录态或门卫问题。门卫已默认提供兜底：探测到宿主无桌面环境时，自动把该按钮改为从门卫下载 `~/.dsh/settings.yaml`（`/__gateway/settings.yaml`，需登录）；桌面环境主机保持 dsh 原生打开。可在配置里关闭（`settingsFileDownload: false`）。

## 技术实现

- 认证：`node:crypto` scrypt（`scrypt$N$r$p$salt$hash` 自描述格式），恒定时间比较防时序攻击；登录时账号不存在也执行等价计算防用户名枚举。
- 会话：内存 `Map` + 过期清理（30 分钟定时 sweep）+ 容量上限（逐出最旧）。
- 反代：流式透传（SSE 长连接友好），剔除 hop-by-hop 头、化解 CL+TE 歧义请求，WebSocket 升级用后端 `rawHeaders` 原样构造 `101` 响应。
- 兼容性补丁：经门卫访问时，用随包自带的**浏览器端 client bundle**（`lib/client.js`）把 dsh 连接标记为 loopback，恢复设置持久化（同时解决「设置-模型」「设置-插件-插件配置」显示问题），不改 dsh 源码；无桌面环境时把「打开配置文件」改为门卫下载。
- 零运行时依赖，所有依赖仅存在于开发/测试环境。

## 测试

```bash
npm test   # node --test test/（零依赖，node:test 内置框架）
```

覆盖：密码哈希与篡改检测、会话过期/容量上限、限速锁定/双维度/TTL、请求头改写与走私防护、注入点边界安全、认证闸门、反代透传、WS 升级握手、setup 引导全流程、改密与会话吊销、审计日志与日志注入净化。

## 目录结构

```text
src/
  index.js        插件主入口：配置校验、路由分发、setup 引导、改密、审计日志、HTTP 服务 + WS 升级
  auth.js         密码哈希（scrypt）、会话存储（容量上限）、登录限速（双维度+TTL）、恒定时间比较
  proxy.js        HTTP 反代（头改写 + hop-by-hop 剔除 + 走私防护）与 WebSocket 升级转发
  user-store.js   用户文件存储（JSON + 原子写入）
  settings-file.js dsh 设置文件下载辅助（无桌面环境兜底）
  login-page.js   登录页 HTML（深色主题，单文件内联）
  setup-page.js   首次启动引导页 HTML（深色主题，单文件内联）
lib/
  client.js       浏览器端 client bundle（标准 dsh.client 接入）：把经门卫访问的连接
                  标记为 loopback，恢复设置持久化与模型/插件配置显示，不改 dsh 源码
bin/
  hash.js         密码哈希生成 CLI
test/
  helpers.js      测试基建：假 cordis ctx / 网关启动器 / 模拟上游 / HTTP 客户端
  auth.test.js    认证核心单测
  proxy.test.js   反代头处理单测
  gateway.test.js 端到端集成测试（认证闸门/反代/setup/WS/改密/审计）
```
