/**
 * gateway 集成测试：真实 HTTP 服务 + 模拟上游，覆盖认证闸门、反代、setup 引导、WS 升级。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

import { startGateway, startUpstream, request, login, cookieOf } from './helpers.js'

test('未登录访问 / 返回登录页并带安全响应头', async () => {
  const gw = await startGateway()
  try {
    const home = await request(gw.port, 'GET', '/')
    assert.equal(home.status, 200)
    assert.match(home.body, /id="login-form"/)
    assert.equal(home.headers['x-frame-options'], 'DENY')
    assert.match(home.headers['content-security-policy'], /default-src 'self'/)
  } finally {
    gw.stop()
  }
})

test('未登录访问其余路径返回 401 JSON', async () => {
  const gw = await startGateway()
  try {
    const api = await request(gw.port, 'GET', '/api/some/resource')
    assert.equal(api.status, 401)
    const data = JSON.parse(api.body)
    assert.ok(data.error)
  } finally {
    gw.stop()
  }
})

test('登录成功种 HttpOnly + SameSite=Strict 会话 Cookie', async () => {
  const gw = await startGateway()
  try {
    const ok = await login(gw.port)
    assert.equal(ok.status, 200)
    assert.deepEqual(JSON.parse(ok.body), { ok: true })
    const c = ok.headers['set-cookie'][0]
    assert.match(c, /^dsh_gw_session=[0-9a-f]{64}/) // 256-bit token
    assert.match(c, /HttpOnly/)
    assert.match(c, /SameSite=Strict/)
    assert.match(c, /Path=\//)
    assert.match(c, /Max-Age=86400/) // 默认 24h
  } finally {
    gw.stop()
  }
})

test('错误密码返回 401 且提示剩余次数', async () => {
  const gw = await startGateway()
  try {
    const bad = await login(gw.port, 'admin', 'nope')
    assert.equal(bad.status, 401)
    const data = JSON.parse(bad.body)
    assert.match(data.error, /用户名或密码错误/)
    assert.match(data.error, /剩余可尝试次数：4/)
  } finally {
    gw.stop()
  }
})

test('同一 IP 连续失败达到上限后锁定（正确密码也拒）', async () => {
  const gw = await startGateway()
  try {
    for (let i = 0; i < 5; i++) {
      const r = await login(gw.port, 'admin', 'nope')
      assert.equal(r.status, 401)
    }
    const locked = await login(gw.port, 'admin', 'password123')
    assert.equal(locked.status, 401)
    assert.match(JSON.parse(locked.body).error, /锁定/)
  } finally {
    gw.stop()
  }
})

test('登录后全量反代：Host/Origin/Sec-Fetch-Site 改写、URL 与响应透传', async () => {
  const calls = []
  const up = await startUpstream((req, res) => {
    calls.push({ url: req.url, host: req.headers.host, origin: req.headers.origin, sfs: req.headers['sec-fetch-site'] })
    res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': 'yes' })
    res.end(JSON.stringify({ upstream: true }))
  })
  const gw = await startGateway({ targetPort: up.port })
  try {
    const cookie = cookieOf(await login(gw.port))
    // 第一次：带外部 Origin
    const r = await request(gw.port, 'GET', '/api/test?x=1', {
      headers: { cookie, host: 'gw.example.com', origin: 'https://gw.example.com' },
    })
    assert.equal(r.status, 200)
    assert.deepEqual(JSON.parse(r.body), { upstream: true })
    assert.equal(r.headers['x-upstream'], 'yes') // 响应头透传
    assert.equal(calls[0].url, '/api/test?x=1') // 路径与查询串透传
    assert.equal(calls[0].host, `127.0.0.1:${up.port}`) // Host 改写为上游形态
    assert.equal(calls[0].sfs, 'same-origin') // Sec-Fetch-Site 补齐
    assert.equal(calls[0].origin, `http://127.0.0.1:${up.port}`) // Origin 改写为 loopback

    // 第二次：不带 Origin 的客户端（curl 等）：不凭空造头，仅补 Sec-Fetch-Site
    const r2 = await request(gw.port, 'GET', '/api/t2', { headers: { cookie } })
    assert.equal(r2.status, 200)
    assert.equal(calls[1].url, '/api/t2')
    assert.equal(calls[1].origin, undefined)
    assert.equal(calls[1].sfs, 'same-origin')
  } finally {
    gw.stop()
    await up.close()
  }
})

test('POST 请求体经反代完整到达上游', async () => {
  let seenBody = ''
  const up = await startUpstream((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seenBody = Buffer.concat(chunks).toString('utf8')
      res.end('ok')
    })
  })
  const gw = await startGateway({ targetPort: up.port })
  try {
    const cookie = cookieOf(await login(gw.port))
    const payload = JSON.stringify({ message: '你好 dsh', n: 42 })
    const r = await request(gw.port, 'POST', '/api/chat', {
      headers: { cookie, 'content-type': 'application/json' },
      body: payload,
    })
    assert.equal(r.status, 200)
    assert.equal(seenBody, payload)
  } finally {
    gw.stop()
    await up.close()
  }
})

test('HTML 响应被注入退出按钮脚本', async () => {
  const up = await startUpstream((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<!doctype html><html><head><title>t</title></head><body>hi</body></html>')
  })
  const gw = await startGateway({ targetPort: up.port })
  try {
    const cookie = cookieOf(await login(gw.port))
    const r = await request(gw.port, 'GET', '/', { headers: { cookie } })
    assert.equal(r.status, 200)
    assert.match(r.body, /dsh-gw-logout-btn/) // 注入的退出按钮
    assert.match(r.body, /<\/head>/) // 结构未破坏
  } finally {
    gw.stop()
    await up.close()
  }
})

test('未登录静态资源 GET 放行', async () => {
  const up = await startUpstream((req, res) => res.end('asset'))
  const gw = await startGateway({ targetPort: up.port })
  try {
    const get = await request(gw.port, 'GET', '/favicon.ico')
    assert.equal(get.status, 200)
    const other = await request(gw.port, 'GET', '/secret.txt')
    assert.equal(other.status, 401) // 白名单外路径不放行
    // 现状记录：白名单路径未区分 HTTP method，POST 也被放行（待加固收紧为仅 GET/HEAD）
    const post = await request(gw.port, 'POST', '/favicon.ico', { body: 'x' })
    assert.equal(post.status, 200)
  } finally {
    gw.stop()
    await up.close()
  }
})

test('登出清除 Cookie 并使旧会话失效', async () => {
  const gw = await startGateway()
  try {
    const cookie = cookieOf(await login(gw.port))
    const out = await request(gw.port, 'POST', '/logout', { headers: { cookie } })
    assert.equal(out.status, 302)
    assert.match(out.headers['set-cookie'][0], /Max-Age=0/)
    const after = await request(gw.port, 'GET', '/api/x', { headers: { cookie } })
    assert.equal(after.status, 401) // 旧会话已不可用
  } finally {
    gw.stop()
  }
})

test('/login 只接受 POST', async () => {
  const gw = await startGateway()
  try {
    const r = await request(gw.port, 'GET', '/login')
    assert.equal(r.status, 405)
  } finally {
    gw.stop()
  }
})

test('非 JSON 请求体登录返回 400', async () => {
  const gw = await startGateway()
  try {
    const r = await request(gw.port, 'POST', '/login', {
      headers: { 'content-type': 'application/json' },
      body: 'not-json',
    })
    assert.equal(r.status, 400)
  } finally {
    gw.stop()
  }
})

test('设置文件下载：未登录 401、登录后 attachment 下发', async () => {
  const gw = await startGateway()
  writeFileSync(path.join(gw.home, 'settings.yaml'), '# test settings\nfoo: bar\n')
  try {
    const noAuth = await request(gw.port, 'GET', '/__gateway/settings.yaml')
    assert.equal(noAuth.status, 401)
    const cookie = cookieOf(await login(gw.port))
    const r = await request(gw.port, 'GET', '/__gateway/settings.yaml', { headers: { cookie } })
    assert.equal(r.status, 200)
    assert.match(r.headers['content-disposition'], /attachment/)
    assert.match(r.headers['content-type'], /text\/yaml/)
    assert.match(r.body, /foo: bar/)
  } finally {
    gw.stop()
  }
})

test('WS 升级未登录被拒（401 后断开），登录后转发 101 并可双向通信', async () => {
  const up = http.createServer(() => {})
  up.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fake-accept\r\n\r\n')
    socket.on('data', (d) => socket.write(d)) // echo
  })
  await new Promise((r) => up.listen(0, '127.0.0.1', r))

  // 原生 socket 手写 upgrade 请求：完全绕开 http client 对"upgrade 被拒即断"的内部 throw，
  // 也更贴近真实浏览器行为。
  const wsRaw = (port, cookie) =>
    new Promise((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1')
      let buf = ''
      const finish = (v) => {
        try {
          sock.destroy()
        } catch {}
        resolve(v)
      }
      sock.setTimeout(2000, () => finish({ kind: 'timeout' }))
      sock.on('error', () => finish({ kind: 'destroyed' }))
      sock.on('connect', () => {
        const key = Buffer.from('0123456789abcdef').toString('base64')
        sock.write(
          `GET /ws HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
            `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n` +
            (cookie ? `Cookie: ${cookie}\r\n` : '') +
            '\r\n',
        )
      })
      sock.on('data', (d) => {
        buf += d.toString('utf8')
        if (/^HTTP\/1\.1 101/.test(buf)) finish({ kind: 'upgraded', head: buf })
        else {
          const m = buf.match(/^HTTP\/1\.1 (\d{3})/)
          if (m && m[1] !== '100') finish({ kind: 'rejected', status: Number(m[1]) })
        }
      })
      sock.on('close', () => finish({ kind: buf.includes('401') ? 'rejected-401-closed' : 'closed' }))
    })

  const gw = await startGateway({ targetPort: up.address().port })
  try {
    const denied = await wsRaw(gw.port, null)
    assert.ok(
      denied.kind === 'rejected' || denied.kind === 'rejected-401-closed' || denied.kind === 'destroyed',
      `未登录 WS 升级应被拒绝，实际 ${denied.kind}`,
    )

    const cookie = cookieOf(await login(gw.port))
    const ok = await wsRaw(gw.port, cookie)
    assert.equal(ok.kind, 'upgraded')
    assert.match(ok.head, /Sec-WebSocket-Accept/)
  } finally {
    gw.stop()
    up.close()
  }
})

test('setup 全流程：日志+文件双通道令牌 → 建号 → 令牌失效 → 410', async () => {
  const gw = await startGateway({}, false) // 未初始化启动
  try {
    // 未初始化时 / 302 到 /setup
    const root = await request(gw.port, 'GET', '/')
    assert.equal(root.status, 302)
    assert.equal(root.headers.location, '/setup')

    // 其余路径引导初始化
    const api = await request(gw.port, 'GET', '/api/x')
    assert.equal(api.status, 401)

    // 三通道之一：日志含令牌
    const line = gw.logs.find((l) => l.includes('一次性令牌'))
    assert.ok(line, '启动日志应包含一次性令牌')
    const token = line.match(/令牌：([A-Z0-9-]+)/)[1]
    assert.ok(/^[A-Z0-9-]+$/.test(token))

    // 文件通道：内容即令牌本身
    const tokenFile = path.join(gw.home, 'setup-token.txt')
    assert.equal(readFileSync(tokenFile, 'utf8'), token)

    // 错误令牌计失败
    const wrong = await request(gw.port, 'POST', '/setup', {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'BAD-BAD-BAD', username: 'u', password: '12345678', password2: '12345678' }),
    })
    assert.equal(wrong.status, 400)
    assert.match(JSON.parse(wrong.body).error, /剩余可尝试次数：4/)

    // 密码过短
    const short = await request(gw.port, 'POST', '/setup', {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, username: 'u', password: 'short', password2: 'short' }),
    })
    assert.equal(short.status, 400)

    // 正确创建管理员
    const ok = await request(gw.port, 'POST', '/setup', {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, username: 'boss', password: 'password123', password2: 'password123' }),
    })
    assert.equal(ok.status, 200)
    assert.ok(existsSync(gw.userStorePath)) // 用户文件落盘
    assert.ok(!existsSync(tokenFile)) // 令牌文件删除

    // 初始化完成后 setup 入口关闭
    const gone = await request(gw.port, 'GET', '/setup')
    assert.equal(gone.status, 410)

    // 新账号可正常登录
    const lg = await login(gw.port, 'boss', 'password123')
    assert.equal(lg.status, 200)
  } finally {
    gw.stop()
  }
})

test('用户文件损坏时启动报错不静默重置', async () => {
  const { apply } = await import('../src/index.js')
  const { makeCtx, tempDir } = await import('./helpers.js')
  const { writeFileSync } = await import('node:fs')
  const dir = tempDir()
  const userStorePath = path.join(dir, 'users.json')
  writeFileSync(userStorePath, '{broken json!!')
  const pack = makeCtx()
  const port = await (await import('./helpers.js')).freePort()
  assert.throws(
    () =>
      apply(pack.ctx, {
        listenHost: '127.0.0.1',
        listenPort: port,
        userStorePath,
        settingsFilePath: path.join(dir, 'settings.yaml'),
      }),
    /用户文件格式错误/,
  )
})
