/**
 * 第七轮（2026-09-10）追加回归：设置文件下载端点。
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { startGateway, request, login, cookieOf, makeCtx } from './helpers.js'

test('设置文件下载：文件缺失时 404 且错误文案不含绝对路径', async () => {
  const gw = await startGateway({ settingsFileDownload: true })
  try {
    const jar = cookieOf(await login(gw.port))
    const res = await request(gw.port, 'GET', '/__gateway/settings.yaml', { headers: { cookie: jar } })
    assert.equal(res.status, 404)
    const body = JSON.parse(res.body)
    assert.equal(body.error, '配置文件不存在')
    assert.ok(!res.body.includes('/tmp/'), '不得泄漏服务器目录结构')
    // 细节进日志（排障有据）
    assert.ok(gw.logs.some((l) => l.includes('设置文件下载失败') && l.includes('settings.yaml')))
  } finally {
    gw.stop()
  }
})

test('设置文件下载：HEAD 仅回响应头，GET 仍下附件', async () => {
  const gw = await startGateway({ settingsFileDownload: true, settingsFilePath: new URL('./fixtures-settings.yaml', import.meta.url).pathname })
  try {
    const jar = cookieOf(await login(gw.port))
    const head = await request(gw.port, 'HEAD', '/__gateway/settings.yaml', { headers: { cookie: jar } })
    assert.equal(head.status, 200)
    assert.equal(head.body, '')
    assert.match(head.headers['content-disposition'] ?? '', /attachment/) // 头与 GET 一致，仅无正文
    assert.equal(head.headers['content-length'], undefined) // HEAD 不声明长度
    const get = await request(gw.port, 'GET', '/__gateway/settings.yaml', { headers: { cookie: jar } })
    assert.equal(get.status, 200)
    assert.match(get.headers['content-disposition'], /attachment/)
  } finally {
    gw.stop()
  }
})

test('设置文件下载：非 GET/HEAD 返回 405', async () => {
  const gw = await startGateway({ settingsFileDownload: true })
  try {
    const jar = cookieOf(await login(gw.port))
    for (const method of ['POST', 'PUT', 'DELETE']) {
      const res = await request(gw.port, method, '/__gateway/settings.yaml', { headers: { cookie: jar } })
      assert.equal(res.status, 405, method)
    }
  } finally {
    gw.stop()
  }
})

test('apply(ctx, null) 不再抛 TypeError（cordis 可能传 null 配置）', async () => {
  const { apply } = await import('../src/index.js')
  const home = mkdtempSync(path.join(tmpdir(), 'gw-nullcfg-'))
  const pack = makeCtx({})
  assert.doesNotThrow(() => {
    apply(pack.ctx, { listenHost: '127.0.0.1', userStorePath: path.join(home, 'users.json'), listenPort: 0 })
  })
  pack.dispose()
  const pack2 = makeCtx({})
  assert.doesNotThrow(() => apply(pack2.ctx, null))
  pack2.dispose()
})
