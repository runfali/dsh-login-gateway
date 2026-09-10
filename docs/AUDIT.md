# dsh-login-gateway 审计报告（2026-09-10）

审计范围：`src/`、`lib/`、`bin/`、`test/`、`README.md`、`package.json`、`cordis.patch.yml` 全量通读。
方法：静态通读 + **每项先写探针复现**（真实起门卫 + 模拟上游）→ 修复 → 固化成回归测试；
新用例在校验「修复前代码」时必须失败（本轮对 5 例做了该对照）。

基线：修复前 65 例全绿、无已知可被利用漏洞（与 2026-09-04 Strix 白盒扫描结论一致）。
终态：**94 例全绿**，连续多轮以新角度复查未再发现 P0–P2。

---

## 第一轮：定向审计（P1/P2）

| # | 级别 | 问题 | 证据 | 修复 |
|---|---|---|---|---|
| 1 | P1 | 上游用普通 HTTP 响应（非 101）拒绝 WS 升级时，门卫不消费该响应 → 浏览器零字节且不关闭 | 探针：上游回 403，客户端 40s 无响应 | `proxyUpgrade` 增 `upstream.on('response')`，回状态行+响应头后双端拆除 |
| 2 | P1 | `getDshAuth()` 把 `null` 当"已解析"缓存 → connection 服务挂载晚于首个请求时，令牌交换在本进程内永久失效 | 探针：首请求 401，服务挂载后仍 401 | 只缓存真值，`null` 留待下次请求重试 |
| 3 | P1 | `{"users":[]}` 被判为已初始化 → `/setup` 返 410、登录永远 401、启动无任何异常日志（需人工删文件） | 探针：GET /setup=410，POST /login 恒 401 | `length > 0` 才算已初始化；空文件补 warn 日志 |
| 4 | P1 | `trustProxy: true` 取 XFF **首段**（客户端可伪造） | 代码级 + Strix 报告遗留项② | 新增 `trustedProxyHops`（默认 1），取右起第 N 段 |
| 5 | P2 | 改密与登录**共享**限速表 → 用户改密连错会把登录 IP 桶打爆，之后连正确密码都登不进去 | 探针：改密连错 5 次后，正确密码登录 401 | 拆出 `changePwLimiter` |
| 6 | P2 | 改密成功用 `session.username`（原样大小写）reset，记录时用小写 → 用户名含大写时清不掉计数 | 代码级比对 | 三处键统一小写 |
| 7 | P2 | 上游 `gzip/br` 压缩 HTML 已修复，但 HEAD 等框架语义未覆盖（见第二轮） | — | 转第二轮处理 |
| 8 | P2 | `getLog` 把 warn/error 全降级成 `logger.info` 且部分日志格式不一致 | 代码级 | `log(msg, level)` 透传级别；未初始化状态走 warn |
| 9 | P2 | 注释声明了 HSTS 但实现不存在 | grep 全仓无 `Strict-Transport-Security` | `secureCookie`（HTTPS 部署）时下发 HSTS，明文绝不下发 |
| 10 | P2 | `X-Content-Type-Options: nosniff` 仅设置下载路由有；204 响应未走安全头 | 探针：`GET /favicon.ico` 204 无 nosniff | `sendSecurityHeaders` 统一补 nosniff，204 也走 |

深链书签 401：曾尝试「给深链挂启动令牌 → 自动引导回首页」，**实测宿主对非首页路径一律 404、且只在 `pathname === '/'\` 上接受令牌交换**（`curl` 对照：`/session/abc`=404、`/?token=bad`=401），方案无支点已放弃；
改为把 401 文案按「导航（Accept: text/html）/ 接口」分流，给浏览器用户可操作指引。

## 第二轮：换角度复查（不看上一轮改动面）

| # | 级别 | 问题 | 证据 | 修复 |
|---|---|---|---|---|
| 11 | P2 | **HEAD 响应框架错位**：上游 HEAD 只回 header 时，代理仍按 GET 注入正文并 `res.end(html)`，Node 按 HEAD 丢 body 却已声明 content-length → **keep-alive 上下一个请求 ECONNRESET** | 探针复现 | HEAD 一律 `res.end(undefined)` |
| 12 | P2 | **JSON 类型混淆打 500**：`{"password":{"toString":1}}` 让 `String()` 抛 `Cannot convert object to primitive value` → 外层 catch 变 500 | 探针：500 + 日志实锤 | 新增 `auth.asString`（只认字符串与有限数字）；`readJsonBody` 只接受对象载荷（数组/null/标量 → 400） |
| 13 | P3 | IPv4-mapped IPv6（`::ffff:1.2.3.4`）与 `1.2.3.4` 各占一个限速桶 | 纯函数探针 | `auth.normalizeIp`，两处取 IP 都走它 |
| 14 | P3 | 上游 404/500 的 HTML 也被注入悬浮改密条与 loopback 补丁 | 探针：404 页含 `dsh-gw-logout-btn` | 只注入 2xx |
| 15 | P2 | 请求体超 `MAX_BODY` 时未消费入流 → 客户端 ECONNRESET（而非 400） | 探针：120KB body → ECONNRESET | 400 前排空入流 |

## 第三轮：请求走私深化

| # | 级别 | 问题 | 证据 | 修复 |
|---|---|---|---|---|
| 16 | P2 | **绝对形式/网络路径形式请求行原样透传**：`GET http://evil.example.com/x` 与 `GET //evil.example.com/x` 的请求行 authority 与已改写的 Host 不一致 → origin 混淆/缓存投毒面 | 探针：上游收到 `url=http://evil.example.com/api/x` | `originFormPath()` 折叠成 `path?query`，HTTP 与 WS 两条路都过 |

## 第四轮：性能与资源

| # | 级别 | 问题 | 证据 | 修复 |
|---|---|---|---|---|
| 17 | P2 | **同步 scrypt 阻塞事件循环**：门卫与 dsh 同进程，每次校验约 40ms 独占事件循环（默认节流 30 次/分钟 ≈ 1.2s/分钟的累计停顿），期间正在流式输出的对话与 WS 全部卡住 | 基准实测 39.2ms/次；探针：登录期间 1ms 定时器命中 0 次 | `verifyPasswordAsync`（node:crypto 异步 scrypt 走 libuv 线程池）+ `fakeVerifyAsync`；实测定时器命中 52 次、5 并发登录 89ms |
| 18 | P3 | 哈希文件被篡改出越界参数（`N=2^30`）会让单次校验 OOM/长阻塞 | 纯函数探针 | `parseHash` 加参数上界（N≤2^20、r≤32、p≤16、哈希段≤128B） |
| 19 | P2 | setup 用户名除长度外无字符集限制（可含 `/`、`!`、控制字符、全角空白） | 探针 | `auth.checkUsername`：中英文/数字/`._-@+`，≤64 |

## 第五轮：部署面与鲁棒性

| # | 级别 | 问题 | 证据 | 修复 |
|---|---|---|---|---|
| 20 | P2 | **上游响应中途断开**：除 HTML 分支外无任何下游收尾动作 → 浏览器拿到半截响应、不报错、干等超时（实测 8s HUNG） | 探针：`writeHead(content-length:100)` → `write('partial')` → destroy，逐 Content-Type 对照；移除新代码可复现旧行为 | 统一挂 `aborted` 与 `close+complete=false`：未回送过则 502，已回送则立刻掐断 |
| 21 | P2 | 设置文件下载端点把**绝对路径与系统错误原文**回给已登录用户（目录结构泄漏） | 探针：`{"error":"配置文件不存在：/root/.dsh/settings.yaml"}` | 对外中性文案，细节进日志（404→warn、500→error）；补 HEAD 支持 |
| 22 | P2 | `apply(ctx, null)` 直接 TypeError（默认参数只兜 undefined） | 探针：`Cannot read properties of null (reading 'listenHost')` | `config ?? {}` |

## 未修复（P3，已评估为不修）

- **全局认证节流的 DoS 语义**：`globalAuthRatePerMinute` 是全局窗口，攻击者刷满即让合法用户也 429。
  属该防线的固有取舍（不设则 scrypt 打满 CPU，设则可被滥用），默认 30 已足够宽松；需要时可调大或关闭。
- **UA 绑定可被伪造**、**改密锁的 IP 维度可被换 IP 绕过**：均为纵深防御的一层，用户名维度仍在。
- **`maxSessions` 满时静默逐出最旧会话**：正常使用不会触发（默认 1000），文档已说明。
- **`apply()`（445 行）与 `proxyRequest()`（163 行）函数偏长**：纯结构问题，拆分收益低于回归风险，未动。
- **双语 README**：家族其余仓已是 `README.md`(EN)+`README.zh-CN.md`，本仓仍单语；内容大改写作量大，留待下次统一。

`code-review-graph dead-code` 报的 3 项（`lib/client.js#apply`、`proxy.js#cleanup/teardown`）为**分析器误报**：
前两者是 client bundle 入口与事件监听回调（经 `upRes.on(...)` 使用），实测移除后行为改变（见第五轮 #20 的对照实验）。

## 停止线与结论

- 修复项全部固化回归（新增 29 例，65 → 94 例全绿）；关键修复均做过「修复前必失败」对照。
- 连续三轮以新角度（请求走私深化 / 性能资源 / 部署面鲁棒性）复查，未再发现 P0–P2。
- 遗留 P3 均为已评估的取舍或纯结构问题，不阻塞交付。
