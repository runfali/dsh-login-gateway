# dsh-login-gateway

DeepSeek Harness（dsh）登录门卫插件：为 dsh Web UI 提供受密码保护的外部访问入口。

dsh Web UI 只监听 `127.0.0.1:3080`，禁止外部访问。本插件随 dsh 启动，额外监听
`0.0.0.0:3081`：未登录时返回中文登录页，已登录后把请求**全量反代**到
`127.0.0.1:3080`（HTTP 与 WebSocket 均支持），功能零缺失。

## 架构

```
外部浏览器 ──► 本插件 0.0.0.0:3081  ──► 127.0.0.1:3080 (dsh Web UI)
              ├─ GET / 未登录  → 中文登录页
              ├─ POST /login   → 校验密码，发放会话 Cookie
              ├─ POST /logout  → 删除会话，跳回登录页
              ├─ 其余路径未登录 → 401 JSON
              └─ 已登录（含 WS）→ 全量反代
```

- 会话 Cookie：`dsh_gw_session`，`HttpOnly + SameSite=Strict + Path=/`
- 会话存储：内存 Map，支持过期清理（每 60 秒 sweep 一次）
- 登录限速：同一 IP 连续失败达到上限后临时锁定，防止暴力破解
- 密码哈希：scrypt（格式 `scrypt$N$r$p$salt$hash`，自描述、换参兼容）
- 反代关键点：改写 `Host / Origin / Sec-Fetch-Site` 为 loopback 形态，使 dsh 的
  trust fence 放行，仅限 loopback 的特权接口（settings/credentials 等）也全部可用

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `src/index.js` | 插件主入口（`name` + `apply(ctx, config)`），路由分发与服务生命周期 |
| `src/auth.js` | 密码哈希、会话存储（SessionStore）、登录限速（LoginLimiter） |
| `src/proxy.js` | HTTP 反代与 WebSocket 升级转发（含头改写、逐跳头剔除） |
| `src/login-page.js` | 中文深色登录页（单文件、内联 CSS/JS、无外部资源） |
| `bin/hash.js` | 密码哈希生成 CLI |

零运行时依赖，仅使用 Node.js 内置模块（`node:http`、`node:crypto`、`node:stream`）。

## 配置项

`config` 字段来自 `cordis.patch.yml`，全部可省略（有默认值），`users` 必填。

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `listenHost` | string | `0.0.0.0` | 外部监听地址 |
| `listenPort` | number | `3081` | 外部监听端口（1-65535） |
| `targetHost` | string | `127.0.0.1` | dsh 反代目标地址 |
| `targetPort` | number | `3080` | dsh 反代目标端口 |
| `sessionTtlHours` | number | `24` | 会话有效期（小时） |
| `maxLoginAttempts` | number | `5` | 同一 IP 允许的连续失败次数 |
| `lockMinutes` | number | `5` | 超过失败次数后的锁定时长（分钟） |
| `users` | array | 必填 | 登录用户列表，每项为 `{ username, passwordHash }` |

非法配置（缺少 `users`、端口越界等）会在加载插件时直接抛错，阻止启动。

## 部署步骤

1. 生成密码哈希：

   ```bash
   node bin/hash.js '你的密码'
   # 或全局安装后：dsh-login-gateway-hash '你的密码'
   ```

2. 在 `cordis.patch.yml` 中注册插件并写入配置：

   ```yaml
   plugins:
     login-gateway:
       config:
         listenHost: 0.0.0.0
         listenPort: 3081
         targetHost: 127.0.0.1
         targetPort: 3080
         sessionTtlHours: 24
         maxLoginAttempts: 5
         lockMinutes: 5
         users:
           - username: admin
             passwordHash: "scrypt$16384$8$1$...."
   ```

   （`passwordHash` 用第 1 步的输出替换）

3. 确保 dsh 能 `import` 本项目的 `src/index.js` 加载插件，然后重启 dsh。

## 使用说明

- 浏览器访问 `http://<服务器IP>:3081`，未登录时显示登录页
- 输入用户名密码登录成功后自动跳转进入 dsh Web 控制台
- 登录页与所有响应均为中文；`/logout` 会清除会话并跳回登录页
- WebSocket（终端等实时通道）同样需要已登录会话，未登录会返回 401 并断开

## 安全说明

- 密码使用 scrypt 加盐哈希存储，仅在服务端保存哈希，不保存明文
- 会话 Cookie 仅限 HttpOnly + SameSite=Strict，防止 XSS 窃取与 CSRF 利用
- 登录接口限流：同一 IP 连续失败 `maxLoginAttempts` 次后锁定 `lockMinutes` 分钟
- 用户不存在时同样执行一次 scrypt 校验，避免通过响应耗时枚举用户名
- `/login` 请求体限制 10KB，防止超大请求拖垮服务
- 会话与限速记录保存在内存中，重启后失效（即：重启后所有人需重新登录）
- 本插件只是访问门卫，建议同时开启系统级防火墙，仅放行必要来源访问 3081 端口
