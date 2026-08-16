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
import os from 'node:os'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

import { hashPassword, LoginLimiter, SessionStore, verifyPassword } from './auth.js'
import { proxyRequest, proxyUpgrade } from './proxy.js'
import { loadUsersSync, saveUsersSync } from './user-store.js'
import { loginPageHtml } from './login-page.js'
import { setupPageHtml } from './setup-page.js'

export const name = 'login-gateway'

const COOKIE_NAME = 'dsh_gw_session'
const MAX_BODY = 100_000
const SWEEP_INTERVAL = 30 * 60_000

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

/** 校验可选种子配置 users：提供时须为非空数组且每项含 username + passwordHash。 */
function validateSeedUsers(users) {
  if (!Array.isArray(users) || users.length === 0) {
    throw new Error('users 配置项必须是非空数组')
  }
  for (const u of users) {
    if (!u || typeof u.username !== 'string' || !u.username || typeof u.passwordHash !== 'string' || !u.passwordHash) {
      throw new Error('users 配置项每项须包含非空 username 与 passwordHash')
    }
  }
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
function sendSecurityHeaders(res) {
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
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
  }
  const seedUsers = config.users
  if (seedUsers !== undefined) validateSeedUsers(seedUsers)

  const log = getLog(ctx)
  const sessions = new SessionStore(cfg.sessionTtlHours * 3600_000)
  const limiter = new LoginLimiter(cfg.maxLoginAttempts, cfg.lockMinutes * 60_000)
  const setupLimiter = new LoginLimiter(cfg.setupMaxAttempts, cfg.setupLockMinutes * 60_000)
  let users = null
  let initialized = false
  let setupToken = null

  // 用户加载优先级：用户文件 > config.users 种子 > 未初始化
  const fileUsers = loadUsersSync(cfg.userStorePath)
  if (fileUsers !== null) {
    users = fileUsers
    initialized = true
    removeSetupToken(cfg.userStorePath, log)
    log(`已从用户文件加载 ${users.length} 个用户`)
  } else if (seedUsers) {
    users = seedUsers
    saveUsersSync(cfg.userStorePath, users)
    initialized = true
    removeSetupToken(cfg.userStorePath, log)
    log(`已从配置写入初始用户文件（${users.length} 个用户）`)
  } else {
    setupToken = randomBytes(16).toString('hex').toUpperCase().replace(/(.{4})(?=.)/g, '$1-')
    // 三通道输出，确保令牌可见：console 直出 stdout + ctx.logger + 写入文件（0600）
    const tokenMsg = `登录门卫未初始化，请访问 http://<主机>:${cfg.listenPort}/setup 并输入一次性令牌：${setupToken}`
    console.log(`[login-gateway] ${tokenMsg}`)
    log(tokenMsg)
    writeSetupToken(cfg.userStorePath, setupToken, log)
  }

  async function handleLogin(req, res) {
    const ip = req.socket.remoteAddress ?? 'unknown'
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
    const preLock = limiter.lockedBy(ip, username)
    if (preLock) return sendJson(res, 401, { error: lockMsg(preLock) })
    const user = users.find((u) => u.username === username)
    if (!user || !verifyPassword(password, user.passwordHash)) {
      const remaining = limiter.recordFailure(ip, username)
      const lock = limiter.lockedBy(ip, username)
      if (lock) return sendJson(res, 401, { error: lockMsg(lock) })
      return sendJson(res, 401, { error: `用户名或密码错误，剩余可尝试次数：${remaining}` })
    }
    limiter.reset(ip, username)
    const token = sessions.create(user.username)
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; Max-Age=${cfg.sessionTtlHours * 3600}; Path=/; HttpOnly; SameSite=Strict`)
    return sendJson(res, 200, { ok: true })
  }

  async function handleSetup(req, res) {
    const ip = req.socket.remoteAddress ?? 'unknown'
    if (setupLimiter.isLocked(ip)) {
      return sendJson(res, 429, { error: `尝试次数过多，已锁定 ${cfg.setupLockMinutes} 分钟，请稍后再试` })
    }
    const fail = (msg) => {
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
    if (token !== setupToken) return fail('一次性令牌不正确')
    if (!username) return fail('用户名不能为空')
    if (username.length > 64) return fail('用户名长度不能超过 64 个字符')
    if (password.length < 8) return fail('密码长度至少 8 位')
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

  async function handle(req, res) {
    const url = new URL(req.url ?? '/', 'http://local')
    const pathname = url.pathname
    const cookies = parseCookies(req.headers.cookie)
    const session = sessions.get(cookies[COOKIE_NAME])

    // 未初始化：只开放 /setup，其余路径引导到初始化
    if (!initialized) {
      if (pathname === '/setup') {
        if (req.method === 'GET') return sendHtml(res, 200, setupPageHtml)
        if (req.method === 'POST') return handleSetup(req, res)
        return sendText(res, 405, '仅支持 GET / POST')
      }
      if (pathname === '/') return sendHtml(res, 200, setupPageHtml)
      return sendJson(res, 401, { error: '登录门卫尚未初始化，请先访问 /setup 完成设置' })
    }

    if (pathname === '/setup') return sendText(res, 410, '初始化已完成，设置入口已关闭')
    if (pathname === '/login') {
      if (req.method !== 'POST') return sendText(res, 405, '仅支持 POST')
      return handleLogin(req, res)
    }
    if (pathname === '/logout') {
      if (req.method !== 'POST') return sendText(res, 405, '仅支持 POST')
      sessions.delete(cookies[COOKIE_NAME])
      res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`)
      sendSecurityHeaders(res)
      res.writeHead(302, { Location: '/' })
      res.end()
      return
    }

    if (!session) {
      if (pathname === '/') return sendHtml(res, 200, loginPageHtml)
      return sendJson(res, 401, { error: '未登录，请先访问 / 登录' })
    }
    return proxyRequest(req, res, cfg.targetHost, cfg.targetPort, cfg.proxyTimeoutMs, cfg.streamIdleTimeoutMs)
  }

  const server = http.createServer((req, res) => {
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

  // WebSocket 升级：先校验会话，通过后才转发给 dsh
  server.on('upgrade', (req, socket, head) => {
    const session = sessions.get(parseCookies(req.headers.cookie)[COOKIE_NAME])
    if (!initialized || !session) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain; charset=utf-8\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src \'self\'; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    proxyUpgrade(req, socket, head, cfg.targetHost, cfg.targetPort, cfg.proxyTimeoutMs)
  })

  // 并发上限 + 收紧超时防 slowloris（Node 默认 headersTimeout 60s 过长）：
  // headersTimeout 15s 内未收全请求头断开；requestTimeout 30s 内未收全请求体断开；
  // keepAliveTimeout 5s 空闲 keep-alive 连接回收，配合 maxConnections 防止连接堆积耗资源。
  server.maxConnections = cfg.maxConnections
  server.headersTimeout = 15_000
  server.requestTimeout = 30_000
  server.keepAliveTimeout = 5_000

  server.once('error', (err) => {
    log(`外部入口启动失败：${err?.message ?? err}`)
  })
  server.listen(cfg.listenPort, cfg.listenHost, () => {
    log(`外部入口已启动：http://${cfg.listenHost}:${cfg.listenPort}（反代至 http://${cfg.targetHost}:${cfg.targetPort}）`)
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
  })
}
