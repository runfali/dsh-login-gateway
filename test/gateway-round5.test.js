/**
 * 第五轮（2026-09-10）追加回归：请求行规范化。
 *
 * 绝对形式（GET http://evil.example.com/x）与网络路径形式（GET //evil.example.com/x）
 * 若不折叠成 origin-form，上游会按请求行里的 authority 解析（Host 已被改写为
 * loopback，两者不一致）→ origin 混淆/缓存投毒面。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'

import { originFormPath } from '../src/proxy.js'
import { startGateway, startUpstream, login, cookieOf } from './helpers.js'

test('originFormPath：绝对形式/网络路径形式一律折叠成 path+query', () => {
  assert.equal(originFormPath('/api/x?a=1'), '/api/x?a=1')
  assert.equal(originFormPath('http://evil.example.com/api/x?a=1'), '/api/x?a=1')
  assert.equal(originFormPath('https://evil.example.com'), '/')
  assert.equal(originFormPath('//evil.example.com/api/x'), '/api/x')
  assert.equal(originFormPath(''), '/')
  assert.equal(originFormPath(undefined), '/')
})

test('反代把绝对形式/网络路径形式折叠成 origin-form 再送上游', async () => {
  const up = await startUpstream((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`up-url=${req.url}`)
  })
  const gw = await startGateway({ targetPort: up.port })
  const raw = (text) =>
    new Promise((resolve, reject) => {
      const sock = net.connect(gw.port, '127.0.0.1')
      let buf = ''
      sock.setTimeout(5000, () => {
        sock.destroy()
        reject(new Error('timeout'))
      })
      sock.on('data', (d) => (buf += d.toString()))
      sock.on('close', () => resolve(buf))
      sock.on('error', reject)
      sock.on('connect', () => sock.write(text))
    })
  try {
    const jar = cookieOf(await login(gw.port))
    const absolute = await raw(`GET http://evil.example.com/api/x?a=1 HTTP/1.1\r\nHost: x\r\nCookie: ${jar}\r\nConnection: close\r\n\r\n`)
    assert.match(absolute, /up-url=\/api\/x\?a=1/)
    const networkPath = await raw(`GET //evil.example.com/api/x HTTP/1.1\r\nHost: x\r\nCookie: ${jar}\r\nConnection: close\r\n\r\n`)
    assert.match(networkPath, /up-url=\/api\/x/)
  } finally {
    gw.stop()
    await up.close()
  }
})
