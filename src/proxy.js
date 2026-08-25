/**
 * dsh-login-gateway 反向代理：HTTP 全量透传 + WebSocket 升级转发。
 * 关键：把外部请求伪装成"本机 loopback 请求"——改写 Host/Origin/Sec-Fetch-Site
 * 三个头，让 dsh 的 /api 信任围栏（trust fence）放行，且特权方法
 * （settings/credentials 等仅限 loopback）也全部可用，功能零缺失。
 * 对缺失浏览器 Fetch Metadata 的请求（curl、隐私浏览器等）补上
 * Sec-Fetch-Site: same-origin，保证依赖同源校验的上游插件路由
 * （如 @anionex/dsh-vision-toolkit 的 paste-policy）也能通过；
 * 已在门卫登录闸门之后，无跨站风险。
 */

import http from 'node:http'

/** HTTP hop-by-hop 头（逐跳头不能透传）。 */
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

/** 攻击者可控、且上游无需信任的代理链头；trustProxy=false 时剥离。 */
const PROXY_CHAIN_HEADERS = ['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip', 'forwarded']

/**
 * 改写请求头：
 * - Host/Origin 换成 loopback 形态，Sec-Fetch-Site 一律 same-origin
 *   （缺失时补齐，保证依赖同源校验的上游插件路由可用）
 * - 剔除全部 hop-by-hop 头（connection/upgrade 等由调用方按需重设；
 *   transfer-encoding 删除后 Node 会按实际流重新分块，顺带化解 CL+TE 走私）
 * - Content-Length 与 Transfer-Encoding 并存时删除两者，杜绝歧义解析
 * - trustProxy=false 时剥离伪造的 XFF/Forwarded 链头，防污染上游日志与判定
 */
export function rewriteHeaders(headers, targetHost, targetPort, { trustProxy = false } = {}) {
  const authority = `${targetHost}:${targetPort}`
  const out = { ...headers }
  // CL+TE 并存属歧义请求（走私经典手法）：先双删，再走 hop-by-hop 清理
  if (out['content-length'] !== undefined && out['transfer-encoding'] !== undefined) {
    delete out['content-length']
  }
  for (const name of Object.keys(out)) {
    if (HOP_BY_HOP.has(name.toLowerCase())) delete out[name]
  }
  if (!trustProxy) {
    for (const h of PROXY_CHAIN_HEADERS) delete out[h]
  }
  if (out.host !== undefined) out.host = authority
  if (out.origin !== undefined) out.origin = `http://${authority}`
  out['sec-fetch-site'] = 'same-origin'
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

/**
 * 客户端 loopback 信任补丁：经门卫反代访问时，浏览器地址栏的 hostname 不是
 * loopback（外部域名/IP），dsh 客户端据此把 connection.isLoopback 判为 false，
 * 导致设置作用域进入 'memory' 模式——设置读取/写入全部被丢弃，表现为改了设置
 * （深色模式、插话发送等）一刷新就还原。
 *
 * 门卫已在服务端把 Host/Origin 改写为 127.0.0.1 形态，服务端信任围栏照常放行，
 * 设置写入会正常落到 ~/.dsh/settings.yaml；本补丁只把浏览器端的连接标记同步为
 * loopback，让 dsh 客户端启用完整的设置持久化（内存态，不触碰 location/origin，
 * 所有请求仍走门卫自身地址；服务端围栏不受影响）。
 *
 * 实现：引导脚本先于应用 bundle 执行，用访问器拦截 window.__ModuleLoader__ 的
 * 安装，把 '@deepseek-ai/dsh-client-connection' 模块的 apply 包一层——应用时把
 * 已提供的 connection handle 的 isLoopback 置为 true。补丁失败只退回"设置不持久化"
 * 的旧行为，不影响应用启动。
 */
const LOOPBACK_PATCH_TAG = `<script>
(function () {
  var FLAG = '__DSH_GW_LOOPBACK_PATCH__'
  if (window[FLAG]) return
  window[FLAG] = true

  var loader = window.__ModuleLoader__
  if (loader && typeof loader.load === 'function') { patchLoader(loader); return }

  var installed
  Object.defineProperty(window, '__ModuleLoader__', {
    configurable: true,
    get: function () { return installed },
    set: function (value) {
      installed = value
      if (value) patchLoader(value)
    }
  })

  function patchLoader(loader) {
    var origLoad = loader.load
    if (typeof origLoad !== 'function' || origLoad.__gwLoopback__) return
    origLoad.__gwLoopback__ = true
    loader.load = function (handoff) {
      if (handoff && handoff.id === '@deepseek-ai/dsh-client-connection' && typeof handoff.factory === 'function') {
        var origFactory = handoff.factory
        handoff.factory = function (require) {
          var mod = origFactory.call(this, require)
          var entry = (mod && mod.exports) ? mod.exports : mod
          if (entry && typeof entry.apply === 'function' && !entry.apply.__gwLoopback__) {
            var origApply = entry.apply
            entry.apply = function (ctx) {
              var result = origApply.apply(this, arguments)
              try {
                var conn = ctx && typeof ctx.get === 'function' ? ctx.get('connection', false) : null
                if (conn && typeof conn === 'object' && !conn.isLoopback) conn.isLoopback = true
              } catch (err) { /* 静默：设置退回不持久化，不影响启动 */ }
              return result
            }
          }
          return mod
        }
      }
      return origLoad.call(this, handoff)
    }
  }
})();
</script>`

/**
 * 设置文件下载兜底脚本：dsh「打开配置文件」依赖宿主机系统级打开
 * （Linux 走 xdg-open / macOS open / Windows Invoke-Item）。无桌面环境
 * （容器、无显示器服务器）上该操作必然失败，前端只显示"无法打开配置文件"。
 * 当门卫探测到宿主无法原生打开时注入本脚本：把该按钮的点击改指到门卫自己的
 * 下载路由（GET /__gateway/settings.yaml，需登录），让远端用户直接取回文件。
 * 仅替换按钮行为，不触碰 dsh 其余界面；桌面环境主机不注入，原生打开不受影响。
 */
const SETTINGS_DOWNLOAD_TAG = `<script>
(function () {
  var LABELS = ['打开配置文件', 'Open configuration file']
  function isSettingsOpenButton(node) {
    while (node && node !== document) {
      if (node.tagName === 'BUTTON') {
        var text = (node.textContent || '').replace(/\s+/g, ' ').trim()
        if (LABELS.indexOf(text) !== -1) return true
      }
      node = node.parentNode
    }
    return false
  }
  document.addEventListener('click', function (e) {
    if (!isSettingsOpenButton(e.target)) return
    e.preventDefault()
    e.stopPropagation()
    window.location.href = '/__gateway/settings.yaml'
  }, true)
})();
</script>`
const INJECT_TAGS = POLYFILL_TAG + LOGOUT_BUTTON_TAG

/**
 * 注入脚本：时机敏感的补丁（loopback 信任）插到 <head> 开标签后，保证先于任何
 * 应用脚本执行；常规注入（polyfill/退出按钮/改密入口）仍在 </head> 前；
 * 无 </head> 则 </body> 前，都没有则追加末尾。
 * 全部用带边界的正则匹配完整开/闭标签，避免 <head> 误匹配 <header>。
 */
function insertAfter(html, regex, insert) {
  const m = html.match(regex)
  if (!m) return null
  const at = m.index + m[0].length
  return html.slice(0, at) + insert + html.slice(at)
}

function insertBefore(html, regex, insert) {
  const m = html.match(regex)
  if (!m) return null
  return html.slice(0, m.index) + insert + html.slice(m.index)
}

const HEAD_OPEN = /<head(\s[^>]*)?>/i
const HEAD_CLOSE = /<\/head\s*>/i
const BODY_CLOSE = /<\/body\s*>/i

function injectTags(html, extraTags = '') {
  const tail = INJECT_TAGS + extraTags
  if (extraTags) {
    let out = insertAfter(html, HEAD_OPEN, extraTags)
    if (out !== null) {
      const withTail = insertBefore(out, HEAD_CLOSE, INJECT_TAGS)
      if (withTail !== null) return withTail
      return out
    }
  }
  const a = insertBefore(html, HEAD_CLOSE, tail)
  if (a !== null) return a
  const b = insertBefore(html, BODY_CLOSE, tail)
  if (b !== null) return b
  return html + tail
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
 * @param {{ clientLoopbackTrust?: boolean, settingsDownload?: boolean }} [injectOpts] HTML 注入开关：
 *   clientLoopbackTrust 注入客户端 loopback 信任补丁（恢复设置持久化），默认 true；
 *   settingsDownload 无桌面环境时注入设置文件下载兜底，默认 false
 */
export function proxyRequest(req, res, targetHost, targetPort, proxyTimeoutMs = 60_000, streamIdleTimeoutMs = 30 * 60_000, injectOpts = {}) {
  const { clientLoopbackTrust = true, settingsDownload = false, trustProxy = false } = injectOpts
  const headers = rewriteHeaders(req.headers, targetHost, targetPort, { trustProxy })
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
        const extraTags = (clientLoopbackTrust ? LOOPBACK_PATCH_TAG : '') + (settingsDownload ? SETTINGS_DOWNLOAD_TAG : '')
        const injected = injectTags(Buffer.concat(chunks).toString('utf8'), extraTags)
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
export function proxyUpgrade(req, socket, head, targetHost, targetPort, proxyTimeoutMs = 60_000, opts = {}) {
  const handshakeTimeout = Math.min(proxyTimeoutMs, 15_000)
  const headers = rewriteHeaders(req.headers, targetHost, targetPort, { trustProxy: Boolean(opts.trustProxy) })
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

/**
 * 宿主是否能『原生打开』文件（dsh 的打开配置文件依赖它）。
 * 与 dsh 的 canOpenNativePath 判定一致：macOS/Windows 恒真；
 * Linux 仅在 WSL 或存在 DISPLAY/WAYLAND_DISPLAY 时为真；
 * 容器/无显示器服务器为假（原生打开必然失败）。
 */
export function nativeOpenAvailable() {
  if (process.platform === 'darwin' || process.platform === 'win32') return true
  if (process.platform !== 'linux') return false
  return Boolean(process.env.WSL_DISTRO_NAME) || Boolean(process.env.DISPLAY) || Boolean(process.env.WAYLAND_DISPLAY)
}
