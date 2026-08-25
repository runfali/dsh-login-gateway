/**
 * 测试基建：假 cordis ctx、临时目录、网关/上游启动器、HTTP 客户端工具。
 * 零外部依赖，仅 node 内置模块。
 */

import net from 'node:net'
import http from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

/** 找一个当前空闲的 TCP 端口（存在微小竞态，测试场景足够）。 */
export function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

/** 假 cordis ctx：收集 effect disposer 与日志。 */
export function makeCtx() {
  const disposers = []
  const logs = []
  return {
    ctx: {
      effect(fn) {
        disposers.push(fn())
      },
      logger() {
        return { info: (...a) => logs.push(a.map(String).join(' ')) }
      },
    },
    logs,
    dispose() {
      for (const d of disposers) {
        try {
          d()
        } catch {
          /* 忽略停机异常 */
        }
      }
    },
  }
}

export function tempDir(prefix = 'gw-test') {
  return mkdtempSync(path.join(tmpdir(), prefix + '-'))
}

function waitForPort(port, host = '127.0.0.1', timeoutMs = 3000) {
  const started = Date.now()
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const sock = net.connect(port, host)
      sock.on('connect', () => {
        sock.destroy()
        resolve()
      })
      sock.on('error', () => {
        sock.destroy()
        if (Date.now() - started > timeoutMs) return reject(new Error(`gateway not listening on ${host}:${port}`))
        setTimeout(attempt, 30)
      })
    }
    attempt()
  })
}

/**
 * 启动门卫插件实例。默认预置已初始化管理员 admin/password123，
 * seedUsers=false 时保持未初始化状态（走 /setup 引导流程测试）。
 * 返回 { port, logs, home, userStorePath, stop }。
 */
export async function startGateway(overrides = {}, seedUsers = true) {
  const [{ apply }, { hashPassword }, { saveUsersSync }] = await Promise.all([
    import('../src/index.js'),
    import('../src/auth.js'),
    import('../src/user-store.js'),
  ])
  const home = tempDir()
  const userStorePath = path.join(home, 'users.json')
  if (seedUsers) {
    saveUsersSync(userStorePath, [
      { username: 'admin', passwordHash: hashPassword('password123'), createdAt: new Date().toISOString() },
    ])
  }
  const pack = makeCtx()
  const cfg = {
    listenHost: '127.0.0.1',
    listenPort: await freePort(),
    userStorePath,
    settingsFilePath: path.join(home, 'settings.yaml'),
    ...overrides,
  }
  apply(pack.ctx, cfg)
  await waitForPort(cfg.listenPort, cfg.listenHost)
  return { port: cfg.listenPort, logs: pack.logs, home, userStorePath, cfg, stop: () => pack.dispose() }
}

/** 启动模拟上游 dsh（普通 HTTP server，可另挂 upgrade 监听）。 */
export async function startUpstream(handler) {
  const server = http.createServer(handler)
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return { port: server.address().port, server, close: () => new Promise((r) => server.close(r)) }
}

/** 小型 HTTP 客户端。body 为字符串/Buffer；无 body 时以 GET 语义收尾。 */
export function request(port, method, p, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () =>
        resolve({
          status: res.statusCode,
          headers: res.headers,
          rawHeaders: res.rawHeaders,
          body: Buffer.concat(chunks).toString('utf8'),
        }),
      )
    })
    req.on('error', reject)
    if (body !== null) req.end(body)
    else req.end()
  })
}

/** 用 admin 凭据登录，返回响应。 */
export function login(port, username = 'admin', password = 'password123') {
  return request(port, 'POST', '/login', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
}

/** 从 Set-Cookie 取裸 cookie 对（name=value）。 */
export function cookieOf(res) {
  const setc = res.headers['set-cookie']
  if (!Array.isArray(setc) || !setc[0]) throw new Error('no Set-Cookie in response')
  return setc[0].split(';')[0]
}
