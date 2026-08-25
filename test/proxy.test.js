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

test('nativeOpenAvailable 与平台环境一致', () => {
  const expect =
    process.platform === 'darwin' || process.platform === 'win32'
      ? true
      : process.platform === 'linux'
        ? Boolean(process.env.WSL_DISTRO_NAME || process.env.DISPLAY || process.env.WAYLAND_DISPLAY)
        : false
  assert.equal(nativeOpenAvailable(), expect)
})
