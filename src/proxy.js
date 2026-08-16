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
 */
export function proxyRequest(req, res, targetHost, targetPort) {
  const headers = rewriteHeaders(req.headers, targetHost, targetPort)
  const upstream = http.request({
    host: targetHost,
    port: targetPort,
    method: req.method,
    path: req.url,
    headers,
  }, (upRes) => {
    res.writeHead(upRes.statusCode ?? 502, stripHopByHop(upRes.headers))
    upRes.pipe(res)
  })
  upstream.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`bad gateway: ${String(err.message ?? err)}`)
    } else {
      res.destroy()
    }
  })
  req.pipe(upstream)
}

/**
 * WebSocket 升级转发：把浏览器到门卫的 upgrade 请求原样转给 dsh，
 * 成功后双向 pipe 两个 socket。
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:stream').Duplex} socket
 * @param {Buffer} head
 */
export function proxyUpgrade(req, socket, head, targetHost, targetPort) {
  const headers = rewriteHeaders(req.headers, targetHost, targetPort)
  headers.connection = 'Upgrade'
  headers.upgrade = 'websocket'

  const upstream = http.request({
    host: targetHost,
    port: targetPort,
    method: 'GET',
    path: req.url,
    headers,
  })

  upstream.on('upgrade', (upRes, upSocket, upHead) => {
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
    socket.on('error', () => upSocket.destroy())
    upSocket.on('error', () => socket.destroy())
  })

  upstream.on('error', () => {
    if (!socket.destroyed) socket.destroy()
  })

  upstream.end()
}
