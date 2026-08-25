/**
 * dsh-login-gateway 插件主入口（cordis 插件，零外部依赖）。
 *
 * 为 dsh Web UI（默认仅 127.0.0.1:3080）提供外部访问入口：
 * 用户名密码登录 + 会话 Cookie + 失败限速 + 全量反向代理（HTTP + WebSocket）。
 * 首次启动可通过 /setup 引导流程创建管理员账号（用户持久化，配置零写死）。
 *
 * 注意：apply 必须是同步函数（cordis 要求 ctx.effect 在 apply 的同步执行段注册，
 * 不允许在 await 之后注册，否则抛 Invalid effect）。启动期 IO 一律用同步版本。
 */

import http from 'node:http'
import https from 'node:https'
import os from 'node:os'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

import { checkNewPassword, fakeVerify, GlobalAuthThrottle, hashPassword, LoginLimiter, safeEqualStr, SessionStore, uaBindKey, verifyPassword } from './auth.js'
import { nativeOpenAvailable, proxyRequest, proxyUpgrade } from './proxy.js'
import { defaultSettingsFilePath, settingsFilePayload } from './settings-file.js'
import { loadUsersSync, saveUsersSync } from './user-store.js'
import { loginPageHtml } from './login-page.js'
import { setupPageHtml } from './setup-page.js'

export const name = 'login-gateway'

const COOKIE_NAME = 'dsh_gw_session'
const MAX_BODY = 100_000
const SWEEP_INTERVAL = 30 * 60_000

/**
 * 浏览器自动请求的静态小资源（PWA manifest / favicon / robots.txt）：
 * 浏览器这些请求默认不带 Cookie。纯静态元数据无敏感信息，未登录也直接放行反代，
 * 保证标签页图标与 PWA 可安装；已登录走正常反代。
 */
const AUTO_RESOURCE_PATHS = new Set([
  '/manifest.webmanifest',
  '/favicon.svg',
  '/favicon.ico',
  '/favicon.png',
  '/apple-touch-icon.png',
  '/robots.txt',
])

/** 取插件日志器；脱离 cordis 环境（直接运行/测试）时退回 console。 */
function getLog(ctx) {
  const logger = ctx?.logger ? ctx.logger('login-gateway') : null
  return logger?.info ? (...args) => logger.info(...args) : (...args) => console.log('[login-gateway]', ...args)
}

function parseCookies(header) {
  const out = {}
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=')
    if (i >= 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim()
  }
  return out
}

/** 读取并解析请求体 JSON；非 JSON 或超大返回 null。 */
async function readJsonBody(req) {
  const chunks = []
  let total = 0
  for await (const chunk of req) {
    chunks.push(chunk)
    total += chunk.length
    if (total > MAX_BODY) return null
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    return null
  }
}

/**
 * 门卫自己生成的响应统一加安全头：防 iframe 嵌入（点击劫持/钓鱼）、
 * 防 Referer 泄漏、CSP 限制加载来源（内联样式/脚本必须 unsafe-inline）。
 * 反代透传的 dsh 响应不加（保持透传原样）。
 */
/** 门卫自产响应统一安全头（认证相关响应一律 no-store 防中间缓存残留）。 */
function sendSecurityHeaders(res) {
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
  res.setHeader('Cache-Control', 'no-store')
}

function sendJson(res, status, data) {
  sendSecurityHeaders(res)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(data))
}

function sendHtml(res, status, html) {
  sendSecurityHeaders(res)
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' })
  res.end(html)
}

function sendText(res, status, text) {
  sendSecurityHeaders(res)
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' })
  res.end(text)
}

/** 一次性令牌文件路径：与用户文件同目录。 */
function setupTokenPath(userStorePath) {
  return path.join(dirname(userStorePath), 'setup-token.txt')
}

/** 把一次性令牌写入文件（权限 0600，内容仅令牌本身），失败仅记录日志不阻塞。 */
function writeSetupToken(userStorePath, token, log) {
  const p = setupTokenPath(userStorePath)
  try {
    mkdirSync(dirname(p), { recursive: true, mode: 0o700 })
    writeFileSync(p, token, { encoding: 'utf8', mode: 0o600 })
    chmodSync(p, 0o600)
  } catch (err) {
    log(`写入一次性令牌文件失败：${err?.message ?? err}`)
  }
}

/** 删除一次性令牌文件（存在才删），失败仅记录日志。 */
function removeSetupToken(userStorePath, log) {
  const p = setupTokenPath(userStorePath)
  try {
    if (existsSync(p)) unlinkSync(p)
  } catch (err) {
    log(`删除一次性令牌文件失败：${err?.message ?? err}`)
  }
}

/** 门卫自身 TLS 配置规范化：enabled 时证书与私钥必须可读，否则显式抛错（fail-fast）。 */
function normalizeTlsConfig(raw) {
  if (!raw || raw.enabled !== true) return null
  if (typeof raw.certPath !== 'string' || typeof raw.keyPath !== 'string') {
    throw new Error('tls.enabled=true 需要提供 tls.certPath 与 tls.keyPath')
  }
  let cert
  let key
  try {
    cert = readFileSync(raw.certPath)
    key = readFileSync(raw.keyPath)
  } catch (err) {
    throw new Error(`TLS 证书/私钥读取失败：${err?.message ?? err}（certPath=${raw.certPath}）`)
  }
  return { cert, key }
}

export function apply(ctx, config = {}) {
  const cfg = {
    listenHost: config.listenHost ?? '0.0.0.0',
    listenPort: config.listenPort ?? 3081,
    targetHost: config.targetHost ?? '127.0.0.1',
    targetPort: config.targetPort ?? 3080,
    sessionTtlHours: config.sessionTtlHours ?? 24,
    maxLoginAttempts: config.maxLoginAttempts ?? 5,
    lockMinutes: config.lockMinutes ?? 5,
    setupMaxAttempts: config.setupMaxAttempts ?? 5,
    setupLockMinutes: config.setupLockMinutes ?? 30,
    proxyTimeoutMs: config.proxyTimeoutMs ?? 60_000,
    streamIdleTimeoutMs: config.streamIdleTimeoutMs ?? 1800_000,
    maxConnections: config.maxConnections ?? 512,
    userStorePath: config.userStorePath ?? path.join(os.homedir(), '.dsh-login-gateway', 'users.json'),
    clientLoopbackTrust: config.clientLoopbackTrust ?? true,
    settingsFilePath: config.settingsFilePath ?? defaultSettingsFilePath(),
    settingsFileDownload: config.settingsFileDownload ?? true,
    // 前置 TLS 反代（nginx/caddy）场景设 true：从 X-Forwarded-For 取真实客户端 IP，
    // 让限速按真实来源生效。直连场景必须保持 false，否则攻击者可伪造 XFF 绕过限速。
    trustProxy: config.trustProxy ?? false,
    // Cookie Secure 标记：未显式配置时跟随 tls.enabled（HTTPS 下自动开启）
    secureCookie: config.secureCookie ?? Boolean(config.tls?.enabled),
    // 会话容量上限：防止反复登录刷爆内存
    maxSessions: config.maxSessions ?? 1000,
    // 全局认证计算节流：每分钟最多允许多少次「触发 scrypt 的尝试」（登录+改密合计），
    // 超限直接 429，不消耗哈希计算——防绕过双维度锁定后打满 CPU
    globalAuthRatePerMinute: config.globalAuthRatePerMinute ?? 30,
    // 会话绑定 User-Agent：HTTP 直连场景下被嗅探的 Cookie 在不同客户端上不可复用；
    // 浏览器升级换 UA 后需重新登录。设 false 可关闭。
    bindUserAgent: config.bindUserAgent ?? true,
  }
  // 门卫自身 TLS（可选）：http+ip 直连场景下为密码与会话提供传输加密。
  // 配置错误必须显式失败——静默回退明文会让用户误以为已加密。
  const tlsCfg = normalizeTlsConfig(config.tls)
  // config.users 种子机制已废弃（会造成"默认用户"）：配置里仍有 users 字段时忽略，不报错。
  // 新装一律强制走 /setup 引导创建账号；本地无用户数据 = 未初始化。
  const log = getLog(ctx)
  const sessions = new SessionStore(cfg.sessionTtlHours * 3600_000, cfg.maxSessions)
  const limiter = new LoginLimiter(cfg.maxLoginAttempts, cfg.lockMinutes * 60_000)
  const setupLimiter = new LoginLimiter(cfg.setupMaxAttempts, cfg.setupLockMinutes * 60_000)
  const authThrottle = new GlobalAuthThrottle(cfg.globalAuthRatePerMinute)
  let users = null
  let initialized = false
  let setupToken = null

  /** 客户端来源 IP：trustProxy 时取 XFF 首段（前置 TLS 反代场景），否则直连 socket 地址。 */
  function getClientIp(req) {
    if (cfg.trustProxy) {
      const xff = req.headers['x-forwarded-for']
      if (typeof xff === 'string' && xff.length > 0) {
        const first = xff.split(',')[0].trim()
        if (first) return first.slice(0, 128)
      }
    }
    return req.socket.remoteAddress ?? 'unknown'
  }

  /** 日志字段净化：防换行/控制字符伪造审计日志条目（日志注入）。 */
  const clean = (s) => String(s ?? '').replace(/[\r\n\t\x00-\x1f]+/g, ' ').slice(0, 64)

  /** 会话 Cookie 值：secureCookie 开启时追加 Secure 标记。 */
  function sessionCookie(value, maxAgeSeconds) {
    const parts = [`${COOKIE_NAME}=${value}`, `Max-Age=${maxAgeSeconds}`, 'Path=/', 'HttpOnly', 'SameSite=Strict']
    if (cfg.secureCookie) parts.push('Secure')
    return parts.join('; ')
  }

  /** secureCookie（即 HTTPS 部署）时对门卫自产响应补 HSTS。 */
  /**
   * 全局认证节流闸：login / change-password 中所有会触发 scrypt 的尝试必须先过。
   * 超限返回 true 并已写好 429 响应。
   */  function authThrottled(req, res, kind) {
    if (authThrottle.acquire()) return false
    log(`认证节流触发 ip=${clean(getClientIp(req))} kind=${kind}`)
    sendJson(res, 429, { error: '尝试过于频繁，请一分钟后再试' })
    return true
  }

  // 用户加载：文件存在 → 已初始化；不存在 → 未初始化
  const fileUsers = loadUsersSync(cfg.userStorePath)
  if (fileUsers !== null) {
    users = fileUsers
    initialized = true
    removeSetupToken(cfg.userStorePath, log)
    log(`已从用户文件加载 ${users.length} 个用户`)
  } else {
    setupToken = randomBytes(16).toString('hex').toUpperCase().replace(/(.{4})(?=.)/g, '$1-')
    // 三通道输出，确保令牌可见：console 直出 stdout + ctx.logger + 写入文件（0600）
    const tokenMsg = `登录门卫未初始化，请访问 http://<主机>:${cfg.listenPort}/setup 并输入一次性令牌：${setupToken}`
    console.log(`[login-gateway] ${tokenMsg}`)
    log(tokenMsg)
    writeSetupToken(cfg.userStorePath, setupToken, log)
  }

  async function handleLogin(req, res) {
    const ip = getClientIp(req)
    if (limiter.isLocked(ip)) {
      return sendJson(res, 401, { error: `失败次数过多，已锁定 ${cfg.lockMinutes} 分钟，请稍后再试` })
    }
    const lockMsg = (dim) => dim === 'username' || dim === 'both'
      ? '该账号已被临时锁定，请稍后再试'
      : `失败次数过多，已锁定 ${cfg.lockMinutes} 分钟，请稍后再试`
    const body = await readJsonBody(req)
    if (body === null) return sendJson(res, 400, { error: '请求体不是有效的 JSON' })
    const username = String(body.username ?? '').trim()
    const password = String(body.password ?? '')
    // 用户名维度的限速键统一小写，防 'Admin'/'ADMIN' 变体稀释锁定
    const usernameKey = username.toLowerCase()
    const preLock = limiter.lockedBy(ip, usernameKey)
    if (preLock) {
      log(`登录拒绝（已锁定） ip=${clean(ip)} user=${clean(username)}`)
      return sendJson(res, 401, { error: lockMsg(preLock) })
    }
    if (authThrottled(req, res, 'login')) return
    const user = users.find((u) => u.username === username)
    if (!user || !verifyPassword(password, user.passwordHash)) {
      if (!user) fakeVerify(password) // 反枚举：不存在也消耗等价计算
      const remaining = limiter.recordFailure(ip, usernameKey)
      const lock = limiter.lockedBy(ip, usernameKey)
      if (lock) {
        log(`登录失败并触发锁定 ip=${clean(ip)} user=${clean(username)}`)
        return sendJson(res, 401, { error: lockMsg(lock) })
      }
      log(`登录失败 ip=${clean(ip)} user=${clean(username)} 剩余=${remaining}`)
      return sendJson(res, 401, { error: `用户名或密码错误，剩余可尝试次数：${remaining}` })
    }
    limiter.reset(ip, usernameKey)
    const token = sessions.create(user.username, cfg.bindUserAgent ? uaBindKey(req.headers['user-agent']) : null)
    res.setHeader('Set-Cookie', sessionCookie(token, cfg.sessionTtlHours * 3600))
    log(`登录成功 ip=${clean(ip)} user=${clean(username)}`)
    return sendJson(res, 200, { ok: true })
  }

  async function handleSetup(req, res) {
    const ip = getClientIp(req)
    if (setupLimiter.isLocked(ip)) {
      return sendJson(res, 429, { error: `尝试次数过多，已锁定 ${cfg.setupLockMinutes} 分钟，请稍后再试` })
    }
    const fail = (msg) => {
      log(`初始化失败 ip=${clean(ip)} 原因=${clean(msg)}`)
      const remaining = setupLimiter.recordFailure(ip)
      if (setupLimiter.isLocked(ip)) {
        return sendJson(res, 429, { error: `尝试次数过多，已锁定 ${cfg.setupLockMinutes} 分钟，请稍后再试` })
      }
      return sendJson(res, 400, { error: `${msg}，剩余可尝试次数：${remaining}` })
    }
    const body = await readJsonBody(req)
    if (body === null) return sendJson(res, 400, { error: '请求体不是有效的 JSON' })
    const token = String(body.token ?? '').trim()
    const username = String(body.username ?? '').trim()
    const password = String(body.password ?? '')
    const password2 = String(body.password2 ?? '')
    if (!safeEqualStr(token, setupToken)) return fail('一次性令牌不正确')
    if (!username) return fail('用户名不能为空')
    if (username.length > 64) return fail('用户名长度不能超过 64 个字符')
    if (password.length < 8) return fail('密码长度至少 8 位')
    const weakReason = checkNewPassword(password)
    if (weakReason) return fail(weakReason)
    if (password !== password2) return fail('两次输入的密码不一致')
    setupLimiter.reset(ip)
    users = [{ username, passwordHash: hashPassword(password), createdAt: new Date().toISOString() }]
    saveUsersSync(cfg.userStorePath, users)
    removeSetupToken(cfg.userStorePath, log)
    initialized = true
    setupToken = null
    log(`初始化完成：管理员账号 ${username} 已创建`)
    return sendJson(res, 200, { ok: true })
  }

  /**
   * 修改密码：需登录会话 + 当前密码验证。
   * 成功后吊销该用户名下除当前会话外的全部会话（凭据轮换后旧凭据残留访问失效）。
   */
  async function handleChangePassword(req, res, session, currentToken) {
    const ip = getClientIp(req)
    if (limiter.isLocked(ip, session.username.toLowerCase())) {
      return sendJson(res, 429, { error: `尝试次数过多，已锁定 ${cfg.lockMinutes} 分钟，请稍后再试` })
    }
    const body = await readJsonBody(req)
    if (body === null) return sendJson(res, 400, { error: '请求体不是有效的 JSON' })
    if (authThrottled(req, res, 'change-password')) return
    const oldPassword = String(body.oldPassword ?? '')
    const newPassword = String(body.newPassword ?? '')
    const newPassword2 = String(body.newPassword2 ?? '')
    const user = users.find((u) => u.username === session.username)
    if (!user || !verifyPassword(oldPassword, user.passwordHash)) {
      const remaining = limiter.recordFailure(ip, session.username.toLowerCase())
      log(`改密失败 ip=${clean(ip)} user=${clean(session.username)} 原因=当前密码错误 剩余=${remaining}`)
      return sendJson(res, 401, { error: '当前密码不正确' })
    }
    if (newPassword.length < 8) return sendJson(res, 400, { error: '新密码长度至少 8 位' })
    if (newPassword.length > 1024) return sendJson(res, 400, { error: '新密码过长' })
    const weakReason = checkNewPassword(newPassword)
    if (weakReason) {
      log(`改密拒绝 user=${clean(session.username)} 原因=弱口令`)
      return sendJson(res, 400, { error: weakReason })
    }
    if (newPassword !== newPassword2) return sendJson(res, 400, { error: '两次输入的新密码不一致' })
    if (newPassword === oldPassword) return sendJson(res, 400, { error: '新密码不能与当前密码相同' })
    user.passwordHash = hashPassword(newPassword)
    saveUsersSync(cfg.userStorePath, users)
    // 吊销该用户其余会话（保留当前），防止旧会话在凭据轮换后继续使用
    let revoked = 0
    for (const [tok, s] of sessions.sessions) {
      if (s.username === session.username && tok !== currentToken) {
        sessions.delete(tok)
        revoked += 1
      }
    }
    limiter.reset(ip, session.username)
    log(`改密成功 ip=${clean(ip)} user=${clean(session.username)} 吊销其他会话 ${revoked} 个`)
    return sendJson(res, 200, { ok: true, revoked })
  }

  async function handle(req, res) {
    const url = new URL(req.url ?? '/', 'http://local')
    const pathname = url.pathname
    const cookies = parseCookies(req.headers.cookie)
    const sessionBindKey = cfg.bindUserAgent ? uaBindKey(req.headers['user-agent']) : undefined
    const session = sessions.get(cookies[COOKIE_NAME], sessionBindKey)

    if (!initialized) {
      if (pathname === '/setup') {
        if (req.method === 'GET') return sendHtml(res, 200, setupPageHtml)
        if (req.method === 'POST') return handleSetup(req, res)
        return sendText(res, 405, '仅支持 GET / POST')
      }
      if (pathname === '/') {
        sendSecurityHeaders(res)
        res.writeHead(302, { Location: '/setup' })
        res.end()
        return
      }
      return sendJson(res, 401, { error: '登录门卫尚未初始化，请先访问 /setup 完成设置' })
    }

    if (pathname === '/setup') return sendText(res, 410, '初始化已完成，设置入口已关闭')
    if (pathname === '/login') {
      if (req.method !== 'POST') return sendText(res, 405, '仅支持 POST')
      return handleLogin(req, res)
    }
    if (pathname === '/logout') {
      if (req.method !== 'POST') return sendText(res, 405, '仅支持 POST')
      const username = session ? clean(session.username) : ''
      sessions.delete(cookies[COOKIE_NAME])
      res.setHeader('Set-Cookie', sessionCookie('', 0))
      log(`登出 user=${username}`)
      sendSecurityHeaders(res)
      res.writeHead(302, { Location: '/' })
      res.end()
      return
    }
    if (!session) {
      // 浏览器自动请求的静态元数据：未登录时由门卫自产——
      // 不反代真 dsh 资源（manifest/favicon 含 "DeepSeek Harness" 指纹，会被针对性扫描利用）。
      // manifest 必须返回合法 JSON（空响应会让浏览器报 "Manifest: Syntax error"），
      // 用极简中性内容占位；robots.txt 明确 Disallow 防搜索引擎收录登录页。
      // 仅放行幂等的 GET/HEAD，其余方法一律拒绝。
      if ((req.method === 'GET' || req.method === 'HEAD') && AUTO_RESOURCE_PATHS.has(pathname)) {
        if (pathname === '/robots.txt') return sendText(res, 200, 'User-agent: *\nDisallow: /\n')
        if (pathname === '/manifest.webmanifest') {
          sendSecurityHeaders(res)
          res.writeHead(200, { 'content-type': 'application/manifest+json; charset=utf-8' })
          res.end('{"name":"Service","short_name":"Service","start_url":"/","scope":"/","display":"standalone","icons":[]}')
          return
        }
        res.writeHead(204)
        res.end()
        return
      }
      if (pathname === '/') return sendHtml(res, 200, loginPageHtml)
      return sendJson(res, 401, { error: '未登录，请先访问 / 登录' })
    }

    // 门卫托管的设置文件下载（需登录）：宿主机无桌面环境时 dsh 原生打开必然失败，
    // 修改密码（需登录）：验证当前密码后轮换哈希并吊销其他会话
    if (pathname === '/change-password') {
      if (req.method !== 'POST') return sendText(res, 405, '仅支持 POST')
      return handleChangePassword(req, res, session, cookies[COOKIE_NAME])
    }
    if (cfg.settingsFileDownload && pathname === '/__gateway/settings.yaml') {
      if (req.method !== 'GET') return sendText(res, 405, '仅支持 GET')
      const payload = settingsFilePayload(cfg.settingsFilePath)
      if (!payload.ok) return sendJson(res, payload.status, { error: payload.reason })
      sendSecurityHeaders(res)
      res.writeHead(payload.status, payload.headers)
      res.end(payload.body)
      return
    }

    return proxyRequest(req, res, cfg.targetHost, cfg.targetPort, cfg.proxyTimeoutMs, cfg.streamIdleTimeoutMs, {
      clientLoopbackTrust: cfg.clientLoopbackTrust,
      settingsDownload: cfg.settingsFileDownload && !nativeOpenAvailable(),
      trustProxy: cfg.trustProxy,
    })
  }

  // 门卫自身 TLS（可选）：启用时 https 承载同一 handler，WS 升级路径不变
  const server = tlsCfg
    ? https.createServer({ cert: tlsCfg.cert, key: tlsCfg.key }, (req, res) => {
        handle(req, res).catch((err) => {
          log(`请求处理出错：${err?.message ?? err}`)
          if (!res.headersSent) {
            sendSecurityHeaders(res)
            res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('内部错误')
          } else {
            res.destroy()
          }
        })
      })
    : http.createServer((req, res) => {
        handle(req, res).catch((err) => {
          log(`请求处理出错：${err?.message ?? err}`)
          if (!res.headersSent) {
            sendSecurityHeaders(res)
            res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('内部错误')
          } else {
            res.destroy()
          }
        })
      })

  // WebSocket 升级：先校验会话（含 UA 绑定），通过后才转发给 dsh
  server.on('upgrade', (req, socket, head) => {
    const bindKey = cfg.bindUserAgent ? uaBindKey(req.headers['user-agent']) : undefined
    const session = sessions.get(parseCookies(req.headers.cookie)[COOKIE_NAME], bindKey)
    if (!initialized || !session) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain; charset=utf-8\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src \'self\'; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    proxyUpgrade(req, socket, head, cfg.targetHost, cfg.targetPort, cfg.proxyTimeoutMs, { trustProxy: cfg.trustProxy })
  })

  // 并发上限 + 收紧超时防 slowloris（Node 默认 headersTimeout 60s 过长）：
  // headersTimeout 15s 内未收全请求头断开；requestTimeout 30s 内未收全请求体断开；
  // keepAliveTimeout 5s 空闲 keep-alive 连接回收，配合 maxConnections 防止连接堆积耗资源。
  server.maxConnections = cfg.maxConnections
  server.headersTimeout = 15_000
  server.requestTimeout = 30_000
  server.keepAliveTimeout = 5_000

  // 持续监听错误（端口占用、运行期 accept 异常等），避免未捕获事件
  server.on('error', (err) => {
    log(`外部入口错误：${err?.message ?? err}`)
  })
  server.listen(cfg.listenPort, cfg.listenHost, () => {
    const addr = server.address()
    const shown = typeof addr === 'object' && addr ? addr.port : cfg.listenPort
    const scheme = tlsCfg ? 'https' : 'http'
    log(`外部入口已启动：${scheme}://${cfg.listenHost}:${shown}（反代至 http://${cfg.targetHost}:${cfg.targetPort}）`)
  })

  const sweepTimer = setInterval(() => {
    sessions.sweep()
    limiter.sweep()
    setupLimiter.sweep()
  }, SWEEP_INTERVAL)
  sweepTimer.unref?.()

  ctx?.effect?.(() => () => {
    clearInterval(sweepTimer)
    server.close()
    // 立即回收全部存活连接（SSE/WS 长连接不阻塞插件停用）
    server.closeIdleConnections?.()
    server.closeAllConnections?.()
  })
}
