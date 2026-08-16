/**
 * dsh-login-gateway 反向代理：HTTP 全量透传 + WebSocket 升级转发。
 * 关键：把外部请求伪装成"本机 loopback 请求"——改写 Host/Origin/Sec-Fetch-Site
 * 三个头，让 dsh 的 /api 信任围栏（trust fence）放行，且特权方法
 * （settings/credentials 等仅限 loopback）也全部可用，功能零缺失。
 */

import http from 'node:http'

/** HTTP hop-by-hop 头（逐跳头不能透传）。 */
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

/** 改写请求头：Host/Origin/Sec-Fetch-Site 换成 loopback 形态。 */
export function rewriteHeaders(headers, targetHost, targetPort) {
  const authority = `${targetHost}:${targetPort}`
  const out = { ...headers }
  delete out['proxy-connection']
  if (out.host !== undefined) out.host = authority
  if (out.origin !== undefined) out.origin = `http://${authority}`
  if (out['sec-fetch-site'] !== undefined) out['sec-fetch-site'] = 'same-origin'
  return out
}

/** 剔除响应里的逐跳头（Node 会自动处理 chunked）。 */
function stripHopByHop(headers) {
  const out = { ...headers }
  for (const name of Object.keys(out)) {
    if (HOP_BY_HOP.has(name.toLowerCase())) delete out[name]
  }
  return out
}

/**
 * HTTP 反代：流式透传（SSE 等长连接天然支持）。
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {number} [proxyTimeoutMs] 上游无响应超时（毫秒），默认 60000
 */
export function proxyRequest(req, res, targetHost, targetPort, proxyTimeoutMs = 60_000) {
  const headers = rewriteHeaders(req.headers, targetHost, targetPort)
  const upstream = http.request({
    host: targetHost,
    port: targetPort,
    method: req.method,
    path: req.url,
    headers,
    agent: false,
  }, (upRes) => {
    res.writeHead(upRes.statusCode ?? 502, stripHopByHop(upRes.headers))
    upRes.pipe(res)
  })
  let timedOut = false
  upstream.setTimeout(proxyTimeoutMs, () => {
    timedOut = true
    upstream.destroy()
    if (!res.headersSent) {
      res.writeHead(504, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('gateway timeout')
    } else {
      res.destroy()
    }
  })
  upstream.on('error', () => {
    if (timedOut) return
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('bad gateway')
    } else {
      res.destroy()
    }
  })
  req.pipe(upstream)
}

/**
 * WebSocket 升级转发：把浏览器到门卫的 upgrade 请求原样转给 dsh，
 * 成功后双向 pipe 两个 socket。握手阶段设置超时（默认不超过 15s）。
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:stream').Duplex} socket
 * @param {Buffer} head
 * @param {number} [proxyTimeoutMs] 握手超时上限（毫秒），取与 15s 的较小值
 */
export function proxyUpgrade(req, socket, head, targetHost, targetPort, proxyTimeoutMs = 60_000) {
  const handshakeTimeout = Math.min(proxyTimeoutMs, 15_000)
  const headers = rewriteHeaders(req.headers, targetHost, targetPort)
  headers.connection = 'Upgrade'
  headers.upgrade = 'websocket'

  const upstream = http.request({
    host: targetHost,
    port: targetPort,
    method: 'GET',
    path: req.url,
    headers,
    agent: false,
  })

  upstream.setTimeout(handshakeTimeout, () => {
    upstream.destroy()
    if (!socket.destroyed) socket.destroy()
  })

  upstream.on('upgrade', (upRes, upSocket, upHead) => {
    upstream.setTimeout(0)
    // 用后端的 rawHeaders 原样构造 101 响应（含 sec-websocket-accept）
    const raw = upRes.rawHeaders ?? []
    let response = 'HTTP/1.1 101 Switching Protocols\r\n'
    for (let i = 0; i + 1 < raw.length; i += 2) {
      response += `${raw[i]}: ${raw[i + 1]}\r\n`
    }
    response += '\r\n'
    socket.write(response)
    if (upHead.length > 0) socket.write(upHead)
    upSocket.pipe(socket)
    socket.pipe(upSocket)
    // 任一侧关闭/报错/收到 FIN，都完整拆除两端，避免半开连接泄漏
    const teardown = () => {
      upSocket.destroy()
      socket.destroy()
    }
    socket.on('error', teardown)
    upSocket.on('error', teardown)
    socket.on('close', teardown)
    upSocket.on('close', teardown)
    socket.on('end', teardown)
    upSocket.on('end', teardown)
  })

  upstream.on('error', () => {
    if (!socket.destroyed) socket.destroy()
  })

  upstream.end()
}
