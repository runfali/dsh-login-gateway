/**
 * 第四轮（2026-09-10）追加回归：极端输入与响应框架正确性。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import { asString, normalizeIp } from '../src/auth.js'
import { startGateway, startUpstream, request, login, cookieOf } from './helpers.js'

test('asString 只认字符串与有限数字，对象/数组/函数一律空串（不再 500）', () => {
  assert.equal(asString('abc'), 'abc')
  assert.equal(asString(42), '42')
  assert.equal(asString(''), '')
  assert.equal(asString(null), '')
  assert.equal(asString(undefined), '')
  assert.equal(asString(NaN), '')
  assert.equal(asString(Infinity), '')
  assert.equal(asString({ toString: 1 }), '') // String(obj) 会抛，必须短路
  assert.equal(asString([1, 2]), '')
  assert.equal(asString(() => {}), '')
})

test('normalizeIp 把 IPv4-mapped IPv6 还原成 IPv4（同一主机不占两个限速桶）', () => {
  assert.equal(normalizeIp('::ffff:1.2.3.4'), '1.2.3.4')
  assert.equal(normalizeIp('::FFFF:1.2.3.4'), '1.2.3.4')
  assert.equal(normalizeIp('1.2.3.4'), '1.2.3.4')
  assert.equal(normalizeIp('::1'), '::1')
  assert.equal(normalizeIp(' 10.0.0.1 '), '10.0.0.1')
  assert.equal(normalizeIp(''), 'unknown')
  assert.equal(normalizeIp(undefined), 'unknown')
})

test('登录：JSON 载荷是对象才受理，数组/null/标量一律 400', async () => {
  const gw = await startGateway()
  try {
    for (const body of ['[]', 'null', '"abc"', '123', 'true']) {
      const r = await request(gw.port, 'POST', '/login', {
        headers: { 'content-type': 'application/json' }, body,
      })
      assert.equal(r.status, 400, body)
    }
  } finally {
    gw.stop()
  }
})

test('登录：类型混淆字段（对象/数组）不再打成 500', async () => {
  const gw = await startGateway()
  try {
    const cases = [
      '{"username":"admin","password":{"toString":1}}',
      '{"username":{"valueOf":1},"password":"x"}',
      '{"username":["a"],"password":["b"]}',
    ]
    for (const body of cases) {
      const r = await request(gw.port, 'POST', '/login', {
        headers: { 'content-type': 'application/json' }, body,
      })
      assert.equal(r.status, 401, body) // 校验失败按凭据错误处理，不是 500
    }
  } finally {
    gw.stop()
  }
})

test('HEAD /：不返回响应体且不声明 content-length（keep-alive 框架不错位）', async () => {
  const up = await startUpstream((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html><head></head><body>up</body></html>')
  })
  const gw = await startGateway({ targetPort: up.port })
  try {
    const jar = cookieOf(await login(gw.port))
    const raw = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port: gw.port, method: 'HEAD', path: '/', headers: { cookie: jar } },
        (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }))
        },
      )
      req.on('error', reject)
      req.end()
    })
    assert.equal(raw.status, 200)
    assert.equal(raw.body, '')
    assert.equal(raw.headers['content-length'], undefined)
    assert.equal(raw.headers['transfer-encoding'], undefined)
  } finally {
    gw.stop()
    await up.close()
  }
})

test('上游错误页（4xx/5xx HTML）不注入门卫脚本，只有 2xx 外壳注入', async () => {
  const up = await startUpstream((req, res) => {
    if (req.url === '/boom') {
      res.writeHead(404, { 'content-type': 'text/html' })
      return res.end('<html><head><title>404</title></head><body>not found</body></html>')
    }
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html><head><title>app</title></head><body>app</body></html>')
  })
  const gw = await startGateway({ targetPort: up.port })
  try {
    const jar = cookieOf(await login(gw.port))
    const bad = await request(gw.port, 'GET', '/boom', { headers: { cookie: jar } })
    assert.equal(bad.status, 404)
    assert.ok(!/dsh-gw-logout-btn/.test(bad.body), '错误页不应被注入')
    const ok = await request(gw.port, 'GET', '/', { headers: { cookie: jar } })
    assert.equal(ok.status, 200)
    assert.match(ok.body, /dsh-gw-logout-btn/)
  } finally {
    gw.stop()
    await up.close()
  }
})

test('请求体超过上限后连接正常收尾（客户端拿到 400，不是 ECONNRESET）', async () => {
  const gw = await startGateway()
  try {
    const r = await request(gw.port, 'POST', '/login', {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'a', password: 'p'.repeat(120_000) }),
    })
    assert.equal(r.status, 400)
  } finally {
    gw.stop()
  }
})
