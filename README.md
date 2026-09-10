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

关键点：反代时把请求头里的 `Host`/`Origin`/`Sec-Fetch-Site` 改写为 loopback 形态，让 dsh 把请求当作"本机请求"信任放行；WebSocket 升级请求同样先校验会话再转发。

**dsh 0.1.2-alpha.1 起 dsh 在信任围栏之外又加了一层「浏览器鉴权」**：首页与全部 `/api`（含 WS 升级）必须携带宿主签发的 `dsh-auth-*` 会话 Cookie，而该 Cookie 只能由启动令牌（打印在服务器终端的 `dsh web: …/?token=…` URL 里）换取。浏览器只见过门卫地址，永远拿不到这个令牌——所以由门卫在「已登录用户的首页导航」上代跑一次令牌交换：

- 令牌只出现在**门卫 → dsh** 这一跳的请求行上，不进入任何下发给浏览器的内容；
- dsh 回 `303 + Set-Cookie`，门卫原样透传，浏览器保存后 `/api` 与 WS 自然带上；
- Cookie 名按 `dsh-auth-` + `base64url(sha256(authority))` 反推（authority 即门卫改写后的 `Host`），据此判断是否需要交换，避免每次导航都重复走 303；
- 自愈：浏览器带着已失效的 `dsh-auth-*`（密钥轮换、过期残留）时，门卫收到宿主的 401 会剥掉坏 Cookie 重跑一次交换，远端用户不必手动清 Cookie；
- 登出门卫时一并吊销该 Cookie（属性与 dsh 签发的那份逐字对齐，否则浏览器删不掉）。

对 dsh ≤ 0.1.1 的宿主，`connection` 服务没有 `authenticatedUrl`，上述逻辑整体跳过，行为与旧版一致。

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
| `trustedProxyHops` | `1` | 仅 `trustProxy: true` 时有意义：可信代理层数，取 XFF **右起第 N 段**作为客户端 IP（前置反代会把直连对端追加在最右，客户端伪造只能往左侧追加）。链路是「CDN → nginx → 门卫」时按可信层数调大（如 2） |
| `secureCookie` | `false` | 仅经 HTTPS 访问门卫时设 `true`：会话 Cookie 追加 `Secure` 标记 |
| `globalAuthRatePerMinute` | `30` | 全局认证节流：每分钟最多 `30` 次触发密码计算的尝试（登录+改密合计，超限直接 429 不消耗计算）。防止攻击者轮换 IP+用户名绕开双维度锁定后打满 CPU |
| `bindUserAgent` | `true` | 会话绑定 User-Agent：被嗅探的 Cookie 在不同客户端上不可复用（异 UA 访问会立即吊销该会话）。浏览器升级换 UA 后需重新登录一次；设 `false` 关闭 |
| `tls` | 不启用 | 门卫自身 TLS。HTTP 直连场景下为密码与会话提供传输加密：`tls: { enabled: true, certPath: '/path/cert.pem', keyPath: '/path/key.pem' }`。启用后 `secureCookie` 自动开启、日志地址变 `https://`。自签证书一行生成见下文「HTTP 直连场景安全清单」。证书路径错误时插件启动显式失败（绝不静默回退明文） |
| `clientLoopbackTrust` | `true` | 经门卫访问时，通过随包自带的浏览器端 client bundle（`lib/client.js`）把 dsh 连接标记为 loopback，恢复设置持久化（深色模式、插话发送等），同时保证「设置-模型」「设置-插件-插件配置」正常显示。设 `false` 可关闭（设置将退回不持久化） |
| `settingsFilePath` | `~/.dsh/settings.yaml` | dsh 设置文件路径（供下载路由使用，一般无需改动） |
| `settingsFileDownload` | `true` | 宿主机无桌面环境（容器/无显示器服务器）时，把 dsh 设置页的「打开配置文件」按钮改为从门卫下载该文件（`/__gateway/settings.yaml`）；桌面环境主机自动保持 dsh 原生打开。设 `false` 关闭该兜底 |

## 使用说明

- **登录**：打开 `http://<主机>:3081/`，输入用户名密码。成功后会种下会话 Cookie（`dsh_gw_session`，`HttpOnly` + `SameSite=Strict`），之后访问全部走反代，包括 WebSocket。
- **修改密码**：页面右下角悬浮栏点「改密」，验证当前密码后设置新密码（至少 8 位）。改密成功会**自动下线该账号的其他所有会话**（当前浏览器保持登录），旧凭据即使泄露也随即失效。
- **登出**：悬浮栏「退出」按钮；无界面时可直接调用：`curl -X POST http://<主机>:3081/logout`。
- **未登录访问**：`/` 返回登录页；其余路径返回 `401` JSON（浏览器导航式请求给「登录已失效，请刷新页面或重新访问 / 登录」，接口请求给「未登录，请先访问 / 登录」）。
- **登录限速**：同一 IP 连续输错 `maxLoginAttempts` 次会被锁定 `lockMinutes` 分钟。被锁定期间即使密码正确也会被拒（`lockMinutes` 后自动解除）。
- **账号锁定**：同一用户名跨 IP 累计失败 `maxLoginAttempts` 次也会被锁定，可防代理池分布式爆破。
- **初始化限速**：`/setup` 同样按 IP 限速，令牌错误、用户名空或不合规、密码过短、两次密码不一致都计失败。
- **改密限速（独立）**：`/change-password` 用独立限速表，连错 `maxLoginAttempts` 次会锁定改密入口 `lockMinutes` 分钟；**不影响用正确密码登录**（登录有自己的桶，登录成功即清零）。用户名合规字符集：中英文、数字与 `._-@+`，≤64 字符。
- **审计日志**：登录成功/失败、锁定触发、登出、改密、初始化全程留痕（含来源 IP 与用户名），可在 dsh 日志中检索 `login-gateway` 前缀审计。

## 安全说明

### HTTP 直连场景安全清单（http://ip:3081 直接使用）

本插件的典型用法就是**不套 nginx、直接 `http://<IP>:3081` 访问**。明文 HTTP 的固有风险是：同一链路上的设备可嗅探到你的密码与会话 Cookie，中间人还可以篡改登录页。门卫已内置多层缓解，按需逐条核对：

1. **传输加密（强烈建议）**：给门卫开自身 TLS——自签证书一行生成：

   ```bash
   mkdir -p ~/.dsh-login-gateway/tls
   openssl req -x509 -newkey rsa:2048 -keyout ~/.dsh-login-gateway/tls/key.pem \
     -out ~/.dsh-login-gateway/tls/cert.pem -days 3650 -nodes -subj '/CN=dsh-gw'
   ```

   然后在 profile 用户层配置里加（整段替换 config 时记得带上其他要改的项）：

   ```yaml
   - id: login-gateway
     config:
       tls: { enabled: true, certPath: '/root/.dsh-login-gateway/tls/cert.pem', keyPath: '/root/.dsh-login-gateway/tls/key.pem' }
       secureCookie: true
   ```

   重启后用 `https://<IP>:3081` 访问；浏览器会提示"证书不受信任"（自签的固有现象），点继续即可——**加密已经生效**，嗅探者只能看到密文。不想看到告警就把 cert.pem 导入系统/浏览器信任库。
2. **会话绑定 UA（默认开启）**：即使 Cookie 被嗅探走，攻击者在自己的客户端上复用会被立即识别并吊销会话。代价：浏览器大版本升级换了 UA 后需要重新登录一次。
3. **爆破防线（默认全开）**：IP+用户名双维度锁定、全局每分钟认证节流（默认 30 次）、密码计算恒时、用户名不存在也消耗等价计算。新设密码会拒绝常见弱口令/纯数字/重复字符——`12345678` 这类密码已无法通过初始化与改密。
4. **未登录零指纹**：登录页之外的静态资源（manifest/favicon）由门卫返回空响应，不再反代真实 dsh 资源——扫描器无法从未登录态确认这是 dsh；robots.txt 明确禁止收录。
5. **限速按直连 IP 生效**：直连场景保持 `trustProxy: false`（默认），伪造 XFF 无法绕过限速。
6. **缩短暴露窗口（可选）**：把 `sessionTtlHours` 从默认 24 调小（如 8），Cookie 泄露后的可用窗口同步变短。

其余通用安全设计见下。

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
- **安全响应头**：门卫自己生成的响应统一带 `X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`X-Content-Type-Options: nosniff` 和 CSP；`secureCookie`（HTTPS 部署）时额外下发 `Strict-Transport-Security: max-age=31536000`，明文部署绝不下发 HSTS。反代透传的 dsh 响应保持原样。
- **请求行规范化**：绝对形式（`GET http://host/x`）与网络路径形式（`GET //host/x`）一律折叠成 `path?query` 再送上游，避免请求行里的 authority 与已改写的 Host 不一致（origin 混淆/缓存投毒面）。
- **密码校验不阻塞服务**：scrypt 走 libuv 线程池（异步）。门卫与 dsh 同进程，同步实现会在每次登录/改密校验时卡住整条事件循环（含正在流式输出的对话）。
- **输入校验与边界**：请求体只接受 JSON 对象、上限 100KB（超限正常回 400 并排空入流，不会 RST 连接）；用户名限中英文/数字与 `._-@+` 且 ≤64 字符；哈希文件被篡改出越界 scrypt 参数（N/r/p 过大）时直接判失败，不会拖垮进程。
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
- 宿主浏览器鉴权适配（dsh ≥ 0.1.2-alpha.1）：`src/index.js` 经宿主公开的 `connection.authenticatedUrl()` 取本进程启动令牌，`src/proxy.js` 在首页导航上代跑令牌交换并处理 401 自愈；门卫与 dsh 同进程，不读任何宿主内部字段。
- 兼容性补丁：经门卫访问时，用随包自带的**浏览器端 client bundle**（`lib/client.js`）把 dsh 连接标记为 loopback，恢复设置持久化（同时解决「设置-模型」「设置-插件-插件配置」显示问题），不改 dsh 源码；无桌面环境时把「打开配置文件」改为门卫下载。
- 零运行时依赖，所有依赖仅存在于开发/测试环境。

## 版本兼容

插件在 `package.json` 中声明了 `dsh.engines.dsh`（`>=0.1.2-alpha.3 <0.2.0`）与
`engines.node`（`^22.19.0 || >=24.0.0`），不匹配的环境下 dsh 会直接拒绝加载。

| dsh | 状态 |
| --- | --- |
| `0.1.0-rc.*` / `0.1.1-rc.*` | ✅ 正常工作（无宿主浏览器鉴权，适配逻辑整体跳过） |
| `0.1.2-alpha.1` 及以上 | ✅ 需要本仓库 ≥ 0.3.0（当前 0.1.2-rc.1）；0.2.0 及更早的门卫版本登录后首页与全部 `/api` 一律 401 |

升级 dsh 后无需改动门卫配置：令牌交换由门卫自动完成，浏览器首次访问首页时静默换取宿主会话。

## 测试

```bash
npm test   # node --test test/（零依赖，node:test 内置框架）
```

覆盖：密码哈希与篡改检测、会话过期/容量上限、限速锁定/双维度/TTL、请求头改写与走私防护、注入点边界安全、认证闸门、反代透传、WS 升级握手（含上游以非 101 拒绝时立刻回传）、setup 引导全流程、改密与会话吊销、审计日志与日志注入净化；以及宿主浏览器鉴权适配（Cookie 名反推对真实抓包向量、令牌交换、失效 Cookie 自愈、令牌不下发浏览器、非首页路径不掺令牌、登出连带吊销宿主会话、旧版宿主行为不变）。

另含 2026-09-10 审计轮次的回归：空 users 文件按未初始化、大小写无关的用户名桶、改密锁与登录锁互不污染、HSTS/nosniff、`trustedProxyHops`、日志分级、HEAD 响应框架、JSON 类型混淆不再 500、IPv4-mapped IPv6 归并、错误页不注入、绝对形式请求行折叠、异步 scrypt 不阻塞事件循环、用户名字符集与哈希参数上界。

> 回归用例的质量标准：每项修复先写探针复现，且新用例在校验「修复前代码」时必须失败（本轮 26 例中 5 例经此对照确认，其余为新增语义覆盖）。

## 目录结构

```text
src/
  index.js        插件主入口：配置校验、路由分发、setup 引导、改密、审计日志、HTTP 服务 + WS 升级
  auth.js         密码哈希（scrypt，含异步校验）、会话存储（容量上限）、登录限速（双维度+TTL）、恒定时间比较、输入规范化（asString/normalizeIp/checkUsername）
  proxy.js        HTTP 反代（头改写 + hop-by-hop 剔除 + 走私防护）、宿主浏览器鉴权交换、WebSocket 升级转发
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
  browser-auth.test.js 宿主浏览器鉴权适配（假 dsh 上游复刻 BrowserAuth 语义）
  gateway-nav.test.js   深链 401 文案与 WS 升级被拒回归
  gateway-round4/5/6.test.js 审计轮次回归（极端输入、请求行规范化、用户名字符集）
```
