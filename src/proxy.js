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
 * 非安全上下文（http:// 非 localhost 等）浏览器不提供 crypto.randomUUID
 * （undefined），但 getRandomValues 可用；注入真随机 UUID v4 polyfill。
 */
const POLYFILL_TAG = '<script>(function(){if(typeof crypto!==\'undefined\'&&typeof crypto.randomUUID!==\'function\'){crypto.randomUUID=function(){var b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;var h=\'\';for(var i=0;i<16;i++){h+=(b[i]<16?\'0\':\'\')+b[i].toString(16);if(i===3||i===5||i===7||i===9)h+=\'-\';}return h;};}})();</script>'

/**
 * 悬浮"退出"按钮：dsh 页面无登出入口，门卫在反代 HTML 时注入。
 * 独立元素 id=dsh-gw-logout-btn，只创建自身不碰其他 DOM；
 * 点击 confirm 后 POST /logout（门卫接口）并跳转登录页。
 */
const LOGOUT_BUTTON_TAG = `<script>
(function(){
  var mount = function(){
    var b = document.createElement('button')
    b.id = 'dsh-gw-logout-btn'
    b.title = '退出登录'
    b.textContent = '退出'
    b.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;padding:6px 14px;font-size:13px;color:#fff;background:rgba(15,16,17,0.8);border:1px solid #2a2c33;border-radius:8px;cursor:pointer;transition:background 0.2s;'
    b.onmouseenter = function(){ b.style.background = 'rgba(40,44,54,0.9)' }
    b.onmouseleave = function(){ b.style.background = 'rgba(15,16,17,0.8)' }
    b.onclick = function(){
      if (!confirm('确定退出登录吗？')) return
      fetch('/logout', { method: 'POST' }).finally(function(){ window.location.href = '/' })
    }
    document.body.appendChild(b)
  }
  if (document.body) mount()
  else document.addEventListener('DOMContentLoaded', mount)
})();
</script>`

const INJECT_TAGS = POLYFILL_TAG + LOGOUT_BUTTON_TAG

/** 在 </head> 前注入脚本（无 </head> 则 </body> 前，都没有则追加末尾）。 */
function injectTags(html) {
  if (html.includes('</head>')) return html.replace('</head>', `${INJECT_TAGS}</head>`)
  if (html.includes('</body>')) return html.replace('</body>', `${INJECT_TAGS}</body>`)
  return html + INJECT_TAGS
}

/**
 * HTTP 反代：流式透传（SSE 等长连接天然支持）。
 * 请求头等待阶段用 proxyTimeoutMs 空闲超时（上游挂起 -> 504）；
 * 响应头到达后清除该超时，改用 streamIdleTimeoutMs 大空闲超时
 * （SSE 长思考间隙不被打断，仅长时间无数据才断开防死连接）。
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {number} [proxyTimeoutMs] 上游响应头等待超时（毫秒），默认 60000
 * @param {number} [streamIdleTimeoutMs] 响应流空闲超时（毫秒），默认 30 分钟
 */
export function proxyRequest(req, res, targetHost, targetPort, proxyTimeoutMs = 60_000, streamIdleTimeoutMs = 30 * 60_000) {
  const headers = rewriteHeaders(req.headers, targetHost, targetPort)
  const upstream = http.request({
    host: targetHost,
    port: targetPort,
    method: req.method,
    path: req.url,
    headers,
    agent: false,
  }, (upRes) => {
    // 响应头已到达：清掉请求头等待期的空闲超时，改对响应流设大的空闲超时
    upstream.setTimeout(0)
    const sock = upRes.socket
    if (sock) {
      sock.setTimeout(streamIdleTimeoutMs, () => {
        upRes.destroy()
        if (!res.destroyed) res.destroy()
      })
      const cleanup = () => sock.setTimeout(0)
      upRes.on('end', cleanup)
      upRes.on('close', cleanup)
    }

    // HTML 响应（dsh index.html 仅 ~12KB）：缓冲后注入 randomUUID polyfill
    const contentType = String(upRes.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase()
    if (contentType === 'text/html') {
      const chunks = []
      upRes.on('data', (c) => chunks.push(c))
      upRes.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
          res.end('bad gateway')
        } else {
          res.destroy()
        }
      })
      upRes.on('end', () => {
        const injected = injectTags(Buffer.concat(chunks).toString('utf8'))
        const outHeaders = stripHopByHop(upRes.headers)
        delete outHeaders['content-length']
        res.writeHead(upRes.statusCode ?? 502, outHeaders)
        res.end(injected)
      })
      return
    }

    // 其他 Content-Type（SSE text/event-stream、json 等）：流式透传不缓冲
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
