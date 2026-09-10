/**
 * 深链 401 文案 + WS 升级被拒 的回归测试。
 *
 * 背景（2026-09-10 审计）：
 * 1) 远端书签深链（如 /session/abc）原先看到裸 401 文本。曾尝试"给深链挂启动令牌
 *    自动引导回首页"，实测宿主对非首页路径一律 404、且只在 pathname '/' 上接受
 *    令牌交换，方案无可靠支点已放弃；最终只把 401 文案按「导航 / 接口」分开，
 *    给浏览器用户可操作的指引。
 * 2) 上游用普通 HTTP 响应拒绝 WS 升级时，门卫原先不消费该响应 → 浏览器无限挂起。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'

import { dshAuthCookieName } from '../src/proxy.js'
import { startGateway, startUpstream, request, login, cookieOf } from './helpers.js'

const LAUNCH_TOKEN = 'nav-token-xyz'
const FRESH = 'v1.nav-fresh'

/** 复刻宿主 BrowserAuth：'/' + 正确 token 才签 Cookie；其余按 Cookie 判 401。 */
function fakeDsh(state) {
  return (req, res) => {
    const u = new URL(req.url ?? '/', 'http://local')
    const cname = dshAuthCookieName(req.headers.host)
    const has = String(req.headers.cookie ?? '').includes(`${cname}=${FRESH}`)
    state.seen.push(req.url)
    if (req.method === 'GET' && u.pathname === '/' && u.searchParams.get('token') === LAUNCH_TOKEN) {
      res.writeHead(303, { 'cache-control': 'no-store', location: '/', 'set-cookie': `${cname}=${FRESH}; Path=/` })
      return res.end()
    }
    if (!has) {
      res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
      return res.end('dsh web authentication required')
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<html><head></head><body>app</body></html>')
  }
}

test('导航式 401（Accept: text/html）给出可操作指引；接口式 401 文案不变', async () => {
  const state = { seen: [] }
  const up = await startUpstream(fakeDsh(state))
  const gw = await startGateway({ targetPort: up.port }, true, {
    connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` },
  })
  try {
    const jar = cookieOf(await login(gw.port))
    // 无门卫会话的深链导航
    const nav = await request(gw.port, 'GET', '/session/abc', { headers: { accept: 'text/html' } })
    assert.equal(nav.status, 401)
    assert.match(JSON.parse(nav.body).error, /刷新|登录/)
    const api = await request(gw.port, 'GET', '/api/x', { headers: { accept: 'application/json' } })
    assert.equal(api.status, 401)
    assert.match(JSON.parse(api.body).error, /未登录/)
    // 不越权：未过闸门的请求一个字节都不落到宿主
    assert.deepEqual(state.seen, [])
    assert.ok(jar)
  } finally {
    gw.stop()
    await up.close()
  }
})

test('已登录的深链在门卫侧照常透传（宿主自己的 404/401 语义不变）', async () => {
  const state = { seen: [] }
  const up = await startUpstream(fakeDsh(state))
  const gw = await startGateway({ targetPort: up.port }, true, {
    connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` },
  })
  try {
    const jar = cookieOf(await login(gw.port))
    const cname = dshAuthCookieName(`127.0.0.1:${up.port}`)
    const deep = await request(gw.port, 'GET', '/session/abc', {
      headers: { cookie: `${jar}; ${cname}=${FRESH}`, accept: 'text/html' },
    })
    assert.equal(deep.status, 200)
    assert.deepEqual(state.seen, ['/session/abc'])
  } finally {
    gw.stop()
    await up.close()
  }
})

test('上游用普通 HTTP 响应拒绝 WS 升级时，浏览器立刻收到该响应而不是挂死', async () => {
  const up = await startUpstream((req, res) => {
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('upgrade refused')
  })
  const gw = await startGateway({ targetPort: up.port })
  try {
    const jar = cookieOf(await login(gw.port))
    const started = Date.now()
    const line = await new Promise((resolve, reject) => {
      const sock = net.connect(gw.port, '127.0.0.1')
      let buf = ''
      const timer = setTimeout(() => {
        sock.destroy()
        reject(new Error(`仍无响应（${Date.now() - started}ms）`))
      }, 5000)
      sock.on('data', (d) => {
        buf += d.toString()
        if (buf.includes('\r\n\r\n')) {
          clearTimeout(timer)
          sock.destroy()
          resolve(buf.split('\r\n')[0])
        }
      })
      sock.on('error', (e) => {
        clearTimeout(timer)
        reject(e)
      })
      sock.on('connect', () =>
        sock.write(
          'GET /ws HTTP/1.1\r\nHost: x\r\nCookie: ' + jar +
          '\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
        ),
      )
    })
    assert.match(line, /^HTTP\/1\.1 403/)
  } finally {
    gw.stop()
    await up.close()
  }
})

test('上游响应中途断开时，门卫立刻收尾（不把连接挂到超时）', async () => {
  const up = await startUpstream((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100' })
    res.write('partial')
    setTimeout(() => res.socket.destroy(), 30)
  })
  const gw = await startGateway({ targetPort: up.port })
  try {
    const jar = cookieOf(await login(gw.port))
    const started = Date.now()
    const outcome = await new Promise((resolve) => {
      const sock = net.connect(gw.port, '127.0.0.1')
      // 必须有 data 监听（消费响应字节）：无消费者的 socket 处于 paused 态，
      // 连 FIN/close 都读不到，用例会假超时（真实浏览器一定在消费）。
      sock.on('data', () => {})
      sock.setTimeout(3000, () => {
        sock.destroy()
        resolve('TIMEOUT')
      })
      sock.on('close', () => resolve('closed'))
      sock.on('error', () => resolve('closed'))
      sock.on('connect', () =>
        sock.write('GET /api/x HTTP/1.1\r\nHost: x\r\nCookie: ' + jar + '\r\nConnection: close\r\n\r\n'),
      )
    })
    const elapsed = Date.now() - started
    assert.equal(outcome, 'closed')
    assert.ok(elapsed < 1500, `应在中断后立刻收尾，实际 ${elapsed}ms`)
  } finally {
    gw.stop()
    await up.close()
  }
})
