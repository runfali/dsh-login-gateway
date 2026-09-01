/**
 * proxy.js 单元测试：请求头改写、平台判定。
 * 反代/WS 转发的端到端行为在 gateway.test.js 集成覆盖。
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { rewriteHeaders, nativeOpenAvailable } from '../src/proxy.js'

test('rewriteHeaders 把 Host/Origin 改写为 loopback 形态', () => {
  const out = rewriteHeaders(
    {
      host: 'gw.example.com',
      origin: 'https://gw.example.com',
      cookie: 'dsh_gw_session=x; other=y',
    },
    '127.0.0.1',
    3080,
  )
  assert.equal(out.host, '127.0.0.1:3080')
  assert.equal(out.origin, 'http://127.0.0.1:3080')
  // 业务头原样保留（会话 Cookie 必须透传）
  assert.equal(out.cookie, 'dsh_gw_session=x; other=y')
})

test('rewriteHeaders 无条件补 Sec-Fetch-Site: same-origin', () => {
  // 浏览器带 cross-site 的场景
  assert.equal(rewriteHeaders({ 'sec-fetch-site': 'cross-site' }, 'h', 1)['sec-fetch-site'], 'same-origin')
  // curl 等不带 Fetch Metadata 的场景
  assert.equal(rewriteHeaders({}, 'h', 1)['sec-fetch-site'], 'same-origin')
})

test('rewriteHeaders 剔除 proxy-connection', () => {
  const out = rewriteHeaders({ 'proxy-connection': 'keep-alive' }, 'h', 1)
  assert.equal(out['proxy-connection'], undefined)
})

test('rewriteHeaders 剔除全部 hop-by-hop 请求头', () => {
  const out = rewriteHeaders(
    {
      connection: 'keep-alive',
      upgrade: 'websocket',
      te: 'trailers',
      trailer: 'x',
      'transfer-encoding': 'chunked',
      'keep-alive': 'timeout=5',
      cookie: 'a=b', // 业务头保留
    },
    'h',
    1,
  )
  for (const h of ['connection', 'upgrade', 'te', 'trailer', 'transfer-encoding', 'keep-alive']) {
    assert.equal(out[h], undefined, `${h} 应被剔除`)
  }
  assert.equal(out.cookie, 'a=b')
})

test('rewriteHeaders CL+TE 并存时双删（防请求走私）', () => {
  const out = rewriteHeaders(
    { 'content-length': '10', 'transfer-encoding': 'chunked' },
    'h',
    1,
  )
  assert.equal(out['content-length'], undefined)
  assert.equal(out['transfer-encoding'], undefined)
})

test('rewriteHeaders trustProxy=false 剥离伪造代理链头；true 时保留', () => {
  const spoof = { 'x-forwarded-for': '1.2.3.4', 'x-real-ip': '1.2.3.4', forwarded: 'for=1.2.3.4' }
  const stripped = rewriteHeaders(spoof, 'h', 1, { trustProxy: false })
  for (const h of Object.keys(spoof)) assert.equal(stripped[h], undefined, `${h} 默认应被剥离`)
  const kept = rewriteHeaders(spoof, 'h', 1, { trustProxy: true })
  assert.equal(kept['x-forwarded-for'], '1.2.3.4')
})

test('injectTags 边界安全：<header> 不被误当 <head>', async () => {
  // 经由真实反代验证注入点选择，见 gateway.test.js；这里直接驱动 proxy.js 内部逻辑
  const { proxyRequest } = await import('../src/proxy.js')
  const { startUpstream } = await import('./helpers.js')
  const http = await import('node:http')

  // 构造含 <header> 的 HTML，确认注入落在 </head> 前且不破坏 <header> 标签
  const up = await startUpstream((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html><head><title>t</title></head><body><header class="top">导航</header></body></html>')
  })
  const srv = http.createServer((req, res) => {
    proxyRequest(req, res, '127.0.0.1', up.port, 5000, 5000, {})
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  try {
    const body = await new Promise((resolve, reject) => {
      http
        .get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
        })
        .on('error', reject)
    })
    assert.match(body, /<header class="top">导航<\/header>/) // <header> 完整保留
    assert.match(body, /dsh-gw-logout-btn/) // 注入存在
    assert.ok(body.indexOf('dsh-gw-logout-btn') < body.indexOf('<body>')) // 注入在 head 区
  } finally {
    await up.close()
    await new Promise((r) => srv.close(r))
  }
})

test('gzip HTML：解压后注入，content-encoding 头被移除', async () => {
  // 回归：dsh 0.1.2-alpha.3 按 Accept-Encoding 返回 gzip HTML，注入前必须解压，
  // 否则浏览器按 content-encoding: gzip 解码注入后的明文 → ERR_CONTENT_DECODING_FAILED
  const zlib = await import('node:zlib')
  const { proxyRequest } = await import('../src/proxy.js')
  const { startUpstream } = await import('./helpers.js')
  const http = await import('node:http')

  const html = '<html><head><title>gzip page</title></head><body><h1>hi</h1></body></html>'
  const up = await startUpstream((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html',
      'content-encoding': 'gzip',
      'content-length': String(zlib.gzipSync(html).length),
    })
    res.end(zlib.gzipSync(html))
  })
  const srv = http.createServer((req, res) => {
    proxyRequest(req, res, '127.0.0.1', up.port, 5000, 5000, {})
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  try {
    const res = await new Promise((resolve, reject) => {
      http
        .get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () =>
            resolve({ headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
          )
        })
        .on('error', reject)
    })
    assert.equal(res.headers['content-encoding'], undefined, 'content-encoding 必须移除')
    assert.match(res.body, /<title>gzip page<\/title>/) // 原始 HTML 完整还原
    assert.match(res.body, /dsh-gw-logout-btn/) // 注入存在
  } finally {
    await up.close()
    await new Promise((r) => srv.close(r))
  }
})

test('br HTML：解压后注入，content-encoding 头被移除', async () => {
  const zlib = await import('node:zlib')
  const { proxyRequest } = await import('../src/proxy.js')
  const { startUpstream } = await import('./helpers.js')
  const http = await import('node:http')

  const html = '<html><head><title>br page</title></head><body><p>hi</p></body></html>'
  const up = await startUpstream((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html',
      'content-encoding': 'br',
      'content-length': String(zlib.brotliCompressSync(html).length),
    })
    res.end(zlib.brotliCompressSync(html))
  })
  const srv = http.createServer((req, res) => {
    proxyRequest(req, res, '127.0.0.1', up.port, 5000, 5000, {})
  })
  await new Promise((r) => srv.listen(0, '127.0.0.1', r))
  try {
    const res = await new Promise((resolve, reject) => {
      http
        .get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () =>
            resolve({ headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
          )
        })
        .on('error', reject)
    })
    assert.equal(res.headers['content-encoding'], undefined)
    assert.match(res.body, /<title>br page<\/title>/)
    assert.match(res.body, /dsh-gw-logout-btn/)
  } finally {
    await up.close()
    await new Promise((r) => srv.close(r))
  }
})

test('nativeOpenAvailable 与平台环境一致', () => {
  const expect =
    process.platform === 'darwin' || process.platform === 'win32'
      ? true
      : process.platform === 'linux'
        ? Boolean(process.env.WSL_DISTRO_NAME || process.env.DISPLAY || process.env.WAYLAND_DISPLAY)
        : false
  assert.equal(nativeOpenAvailable(), expect)
})
