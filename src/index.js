/**
 * dsh-login-gateway 插件主入口。
 *
 * 行为：外部监听 0.0.0.0:3081，未登录返回中文登录页，已登录将请求
 * 全量反代到 127.0.0.1:3080（HTTP + WebSocket）。
 * 插件 API：export const name = "login-gateway"; export function apply(ctx, config)。
 */

import http from 'node:http'
import { loginPageHtml } from './login-page.js'
import { SessionStore, LoginLimiter, verifyPassword, hashPassword } from './auth.js'
import { proxyRequest, proxyUpgrade } from './proxy.js'

export const name = 'login-gateway'

const COOKIE_NAME = 'dsh_gw_session'
const MAX_BODY_BYTES = 10 * 1024 // /login 请求体上限 10KB
const SWEEP_INTERVAL_MS = 60_000
// 等时化占位哈希：与真实用户哈希同一参数，防止通过响应耗时枚举用户名
const DUMMY_HASH = hashPassword('dsh-login-gateway-placeholder')

const DEFAULTS = {
  listenHost: '0.0.0.0',
  listenPort: 3081,
  targetHost: '127.0.0.1',
  targetPort: 3080,
  sessionTtlHours: 24,
  maxLoginAttempts: 5,
  lockMinutes: 5,
}

/** 校验并归一化配置，非法配置直接抛 Error。 */
function parseConfig(input) {
  const cfg = { ...DEFAULTS, ...(input ?? {}) }

  const asString = (value, key) => {
    if (typeof value !== 'string' || !value) {
      throw new Error(`配置 ${key} 必须是非空字符串，当前值：${JSON.stringify(value)}`)
    }
    return value
  }
  const asPort = (value, key) => {
    const n = Number(value)
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      throw new Error(`配置 ${key} 必须是 1-65535 的整数，当前值：${JSON.stringify(value)}`)
    }
    return n
  }
  const asPositive = (value, key) => {
    const n = Number(value)
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`配置 ${key} 必须是正数，当前值：${JSON.stringify(value)}`)
    }
    return n
  }
  const asInt = (value, key) => {
    const n = Number(value)
    if (!Number.isInteger(n) || n <= 0) {
      throw new Error(`配置 ${key} 必须是正整数，当前值：${JSON.stringify(value)}`)
    }
    return n
  }

  if (!Array.isArray(cfg.users) || cfg.users.length === 0) {
    throw new Error('配置 users 必须是非空数组（至少包含一个用户）')
  }
  const users = cfg.users.map((u) => {
    if (!u || typeof u.username !== 'string' || !u.username ||
        typeof u.passwordHash !== 'string' || !u.passwordHash) {
      throw new Error(`配置 users 的每一项必须包含非空的 username 与 passwordHash 字符串，非法项：${JSON.stringify(u)}`)
    }
    return { username: u.username, passwordHash: u.passwordHash }
  })

  return {
    listenHost: asString(cfg.listenHost, 'listenHost'),
    listenPort: asPort(cfg.listenPort, 'listenPort'),
    targetHost: asString(cfg.targetHost, 'targetHost'),
    targetPort: asPort(cfg.targetPort, 'targetPort'),
    sessionTtlHours: asPositive(cfg.sessionTtlHours, 'sessionTtlHours'),
    maxLoginAttempts: asInt(cfg.maxLoginAttempts, 'maxLoginAttempts'),
    lockMinutes: asPositive(cfg.lockMinutes, 'lockMinutes'),
    users,
  }
}

/** 解析 Cookie 头为对象。 */
function parseCookies(header) {
  const out = {}
  if (!header) return out
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim()
  }
  return out
}

/** 从请求 Cookie 解析会话，返回用户名，未登录返回 null。 */
function getSessionUser(req, sessions) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME]
  if (!token) return null
  const session = sessions.get(token)
  return session ? session.username : null
}

/** 读取请求体，超过 10KB 返回 null（超限后丢弃剩余数据，不缓存，避免背压死锁）。 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    let tooLarge = false
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        tooLarge = true
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(tooLarge ? null : Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function sendJson(res, status, data, extraHeaders = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  })
  res.end(JSON.stringify(data))
}

function sendLoginPage(res) {
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(loginPageHtml)
}

function sessionCookie(token, ttlSeconds) {
  return `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.max(1, Math.floor(ttlSeconds))}`
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
}

async function handleLogin(req, res, cfg, sessions, limiter) {
  const ip = req.socket.remoteAddress ?? 'unknown'
  if (limiter.isLocked(ip)) {
    return sendJson(res, 401, {
      ok: false,
      error: '登录失败次数过多，该 IP 已被临时锁定，请稍后再试',
      locked: true,
    })
  }

  let body
  try {
    body = await readBody(req)
  } catch {
    return sendJson(res, 400, { ok: false, error: '请求体读取失败' })
  }
  if (body === null) {
    return sendJson(res, 400, { ok: false, error: '请求体过大（超过 10KB）' })
  }

  let payload
  try {
    payload = JSON.parse(body)
  } catch {
    return sendJson(res, 400, { ok: false, error: '请求格式错误，请提交 JSON' })
  }

  const username = payload?.username
  const password = payload?.password
  const user = cfg.users.find((u) => u.username === username)
  // 等时化：用户不存在时也走一遍 scrypt，避免通过耗时枚举用户名
  const verified = verifyPassword(String(password ?? ''), user ? user.passwordHash : DUMMY_HASH)
  const ok = !!user && verified

  if (!ok) {
    const remaining = limiter.recordFailure(ip)
    if (remaining <= 0) {
      return sendJson(res, 401, {
        ok: false,
        error: '登录失败次数过多，该 IP 已被临时锁定，请稍后再试',
        locked: true,
      })
    }
    return sendJson(res, 401, { ok: false, error: '用户名或密码错误', remaining })
  }

  limiter.reset(ip)
  const token = sessions.create(username)
  const ttlSeconds = cfg.sessionTtlHours * 3600
  return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(token, ttlSeconds) })
}

function handleRequest(req, res, cfg, sessions, limiter) {
  const pathname = new URL(req.url, 'http://localhost').pathname
  const sessionUser = getSessionUser(req, sessions)

  // 未登录访问首页 → 登录页
  if (req.method === 'GET' && pathname === '/') {
    if (sessionUser) return proxyRequest(req, res, cfg.targetHost, cfg.targetPort)
    return sendLoginPage(res)
  }

  if (req.method === 'POST' && pathname === '/login') {
    return handleLogin(req, res, cfg, sessions, limiter)
  }

  if (req.method === 'POST' && pathname === '/logout') {
    const token = parseCookies(req.headers.cookie)[COOKIE_NAME]
    if (token) sessions.delete(token)
    res.writeHead(302, { Location: '/', 'Set-Cookie': clearSessionCookie() })
    return res.end()
  }

  // 其余路径：未登录一律 401 JSON，已登录全量反代
  if (!sessionUser) {
    return sendJson(res, 401, { ok: false, error: '未登录，请先访问登录页完成验证' })
  }
  proxyRequest(req, res, cfg.targetHost, cfg.targetPort)
}

function handleUpgrade(req, socket, head, cfg, sessions) {
  if (!getSessionUser(req, sessions)) {
    if (!socket.destroyed) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
      socket.destroy()
    }
    return
  }
  proxyUpgrade(req, socket, head, cfg.targetHost, cfg.targetPort)
}

/**
 * 插件入口。
 * @param {import('cordis').Context} ctx
 * @param {object} config 来自 cordis.patch.yml 的 config 字段
 */
export function apply(ctx, config) {
  const cfg = parseConfig(config)
  const sessions = new SessionStore(cfg.sessionTtlHours * 3600_000)
  const limiter = new LoginLimiter(cfg.maxLoginAttempts, cfg.lockMinutes * 60_000)

  const log = (...args) => {
    if (ctx.logger?.info) ctx.logger.info(...args)
    else console.log(...args)
  }

  const server = http.createServer((req, res) => handleRequest(req, res, cfg, sessions, limiter))
  server.on('upgrade', (req, socket, head) => handleUpgrade(req, socket, head, cfg, sessions))
  server.on('error', (err) => ctx.logger?.error?.(`登录门卫服务异常：${err.message ?? err}`))

  server.listen(cfg.listenPort, cfg.listenHost, () => {
    log(`登录门卫已启动：http://${cfg.listenHost}:${cfg.listenPort} → ${cfg.targetHost}:${cfg.targetPort}`)
  })

  const sweepTimer = setInterval(() => sessions.sweep(), SWEEP_INTERVAL_MS)
  sweepTimer.unref?.()

  ctx.effect(() => () => {
    clearInterval(sweepTimer)
    server.closeAllConnections?.()
    server.close()
  })
}
