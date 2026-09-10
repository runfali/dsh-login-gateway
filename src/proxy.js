/**
 * dsh-login-gateway 反向代理：HTTP 全量透传 + WebSocket 升级转发。
 * 关键：把外部请求伪装成"本机 loopback 请求"——改写 Host/Origin/Sec-Fetch-Site
 * 三个头，让 dsh 的 /api 信任围栏（trust fence）放行，且特权方法
 * （settings/credentials 等仅限 loopback）也全部可用，功能零缺失。
 * 对缺失浏览器 Fetch Metadata 的请求（curl、隐私浏览器等）补上
 * Sec-Fetch-Site: same-origin，保证依赖同源校验的上游插件路由
 * （如 @anionex/dsh-vision-toolkit 的 paste-policy）也能通过；
 * 已在门卫登录闸门之后，无跨站风险。
 *
 * dsh 0.1.2-alpha.1 起，改三头只够过"信任围栏"（403），过不了新增的
 * "浏览器鉴权"（401）：首页与全部 /api 请求都必须携带宿主签发的 dsh-auth-*
 * 会话 Cookie。本文件因此额外承担一次由门卫代跑的令牌交换，详见 dshAuth 一节。
 */

import http from 'node:http'
import { createHash } from 'node:crypto'
import zlib from 'node:zlib'

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
  delete out['proxy-connection']
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

// ---------------------------------------------------------------------------
// dsh 浏览器鉴权（0.1.2-alpha.1+）
// ---------------------------------------------------------------------------

/**
 * 宿主 BrowserAuth 的会话 Cookie 名：'dsh-auth-' + base64url(sha256(authority))，
 * authority 是请求 Host 头的 WHATWG 规范化结果。门卫把 Host 改写成
 * targetHost:targetPort，所以必须用同一个 authority 反推 Cookie 名，
 * 才能判断浏览器是否已经持有宿主会话（避免每次导航都重复交换）。
 */
export function dshAuthCookieName(authority) {
  const digest = createHash('sha256').update(authority).digest('base64')
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
  return `dsh-auth-${digest}`
}

/** 把宿主启动令牌附加到请求路径上。仅用于门卫→宿主这一跳，令牌绝不下发给浏览器。 */
export function withLaunchToken(url, token) {
  const u = new URL(url ?? '/', 'http://local')
  u.searchParams.set('token', token)
  return `${u.pathname}${u.search}`
}

/** Cookie 头里是否已含指定名字的项。 */
function hasCookieNamed(header, name) {
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=')
    if (i >= 0 && part.slice(0, i).trim() === name) return true
  }
  return false
}

/** 从 Cookie 头里摘掉指定名字的项（丢弃已失效的宿主会话，为重新交换让路）。 */
function withoutCookie(header, name) {
  return String(header ?? '')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s && s.split('=')[0] !== name)
    .join('; ')
}

/**
 * 首页导航判定：只有 GET/HEAD、无请求体、pathname 恰为 '/' 且未自带 token 时，
 * 门卫才代跑令牌交换。宿主也只在 pathname '/' 上接受交换（authorizeIndex），
 * 其余路径一律按 Cookie 判定，门卫不越权插手。
 */
function isIndexNavigation(req) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false
  // 有请求体时不重试：入流已被第一次尝试消费掉，重放会丢正文
  if (req.headers['content-length'] !== undefined || req.headers['transfer-encoding'] !== undefined) return false
  try {
    const u = new URL(req.url ?? '/', 'http://local')
    return u.pathname === '/' && !u.searchParams.has('token')
  } catch {
    return false
  }
}

/**
 * 非安全上下文（http:// 非 localhost 等）浏览器不提供 crypto.randomUUID
 * （undefined），但 getRandomValues 可用；注入真随机 UUID v4 polyfill。
 */
const POLYFILL_TAG = '<script>(function(){if(typeof crypto!==\'undefined\'&&typeof crypto.randomUUID!==\'function\'){crypto.randomUUID=function(){var b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;var h=\'\';for(var i=0;i<16;i++){h+=(b[i]<16?\'0\':\'\')+b[i].toString(16);if(i===3||i===5||i===7||i===9)h+=\'-\';}return h;};}})();</script>'

/**
 * 悬浮"改密 / 退出"栏：dsh 页面无账号管理入口，门卫在反代 HTML 时注入。
 * - 退出：confirm 后 POST /logout 并跳回登录页
 * - 改密：内联对话框（当前密码 + 新密码 ×2）POST /change-password；
 *   成功后服务端吊销其余会话，本会话保留。
 * 全部 DOM API 构建，不碰 dsh 自身节点；样式与登录页同风格。
 */
const LOGOUT_BUTTON_TAG = `<script>
(function(){
  var css = 'padding:6px 14px;font-size:13px;color:#fff;background:rgba(15,16,17,0.8);border:1px solid #2a2c33;border-radius:8px;cursor:pointer;transition:background 0.2s;'
  var openDialog = function(){
    if (document.getElementById('dsh-gw-pw-overlay')) return
    var overlay = document.createElement('div')
    overlay.id = 'dsh-gw-pw-overlay'
    overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(1,1,2,0.72);display:flex;align-items:center;justify-content:center;'
    var card = document.createElement('div')
    card.style.cssText = 'width:min(92vw,360px);background:#141516;border:1px solid #2a2c33;border-radius:12px;padding:24px;font-size:13px;color:#f7f8f8;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;'
    var title = document.createElement('div'); title.textContent = '修改密码'; title.style.cssText='font-size:15px;margin-bottom:14px;'
    card.appendChild(title)
    var fields = [['当前密码','old-password'],['新密码（至少8位）','new-password'],['确认新密码','new-password2']]
    var inputs = []
    fields.forEach(function(f){
      var label = document.createElement('div'); label.textContent = f[0]; label.style.cssText='margin:10px 0 6px;color:#d0d6e0;'
      var input = document.createElement('input')
      input.type = 'password'; input.placeholder = '请输入' + f[0]
      input.style.cssText = 'width:100%;box-sizing:border-box;padding:9px 11px;font-size:13px;color:#f7f8f8;background:#010102;border:1px solid #2a2c33;border-radius:8px;outline:none;'
      input.dataset.field = f[1]
      label.appendChild(input); card.appendChild(label); inputs.push(input)
    })
    var msg = document.createElement('div'); msg.style.cssText='min-height:16px;margin-top:10px;color:#ff6363;font-size:12px;'; msg.setAttribute('role','alert')
    var row = document.createElement('div'); row.style.cssText='display:flex;gap:8px;margin-top:12px;'
    var cancel = document.createElement('button'); cancel.textContent='取消'
    cancel.style.cssText = css + 'flex:1;background:#1c1e22;'
    var submit = document.createElement('button'); submit.textContent='确认修改'
    submit.style.cssText = css + 'flex:1;background:#3d5af0;border-color:#3d5af0;'
    row.appendChild(cancel); row.appendChild(submit); card.appendChild(row); card.appendChild(msg)
    overlay.appendChild(card); document.body.appendChild(overlay)
    var close = function(){ overlay.remove() }
    cancel.onclick = close
    overlay.onclick = function(e){ if (e.target === overlay) close() }
    submit.onclick = function(){
      msg.textContent = ''
      var v = {}
      inputs.forEach(function(i){ v[i.dataset.field] = i.value })
      if (!v['old-password'] || !v['new-password']) { msg.textContent = '请填写完整'; return }
      if (v['new-password'] !== v['new-password2']) { msg.textContent = '两次输入的新密码不一致'; return }
      submit.disabled = true
      fetch('/change-password', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ oldPassword: v['old-password'], newPassword: v['new-password'], newPassword2: v['new-password2'] })
      }).then(function(r){ return r.json().catch(function(){ return {} }) }).then(function(data){
        submit.disabled = false
        if (data && data.ok) {
          msg.style.color = '#7ee787'
          msg.textContent = '修改成功' + (data.revoked ? ('，已下线其他会话 ' + data.revoked + ' 个') : '')
          setTimeout(close, 1500)
        } else {
          msg.textContent = (data && data.error) || '修改失败，请重试'
        }
      }).catch(function(){ submit.disabled = false; msg.textContent = '网络错误，请重试' })
    }
  }
  var mount = function(){
    var bar = document.createElement('div')
    bar.id = 'dsh-gw-bar'
    bar.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;display:flex;gap:8px;'
    var mkBtn = function(id, txt){
      var b = document.createElement('button')
      b.id = id; b.textContent = txt; b.title = txt; b.style.cssText = css
      b.onmouseenter = function(){ b.style.background = 'rgba(40,44,54,0.9)' }
      b.onmouseleave = function(){ b.style.background = 'rgba(15,16,17,0.8)' }
      return b
    }
    var pw = mkBtn('dsh-gw-changepw-btn', '改密')
    pw.onclick = openDialog
    var logout = mkBtn('dsh-gw-logout-btn', '退出')
    logout.onclick = function(){
      if (!confirm('确定退出登录吗？')) return
      fetch('/logout', { method: 'POST' }).finally(function(){ window.location.href = '/' })
    }
    bar.appendChild(pw); bar.appendChild(logout)
    document.body.appendChild(bar)
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
 * @param {{ clientLoopbackTrust?: boolean, settingsDownload?: boolean, trustProxy?: boolean, dshAuth?: {cookieName: string, token: string}|null }} [injectOpts]
 *   HTML 注入与宿主鉴权开关：clientLoopbackTrust 注入客户端 loopback 信任补丁
 *   （恢复设置持久化），默认 true；settingsDownload 无桌面环境时注入设置文件下载兜底，
 *   默认 false；dshAuth 为 null（旧版宿主或未挂载 connection 服务）时完全跳过鉴权适配。
 */
export function proxyRequest(req, res, targetHost, targetPort, proxyTimeoutMs = 60_000, streamIdleTimeoutMs = 30 * 60_000, injectOpts = {}) {
  const { clientLoopbackTrust = true, settingsDownload = false, trustProxy = false, dshAuth = null } = injectOpts
  const headers = rewriteHeaders(req.headers, targetHost, targetPort, { trustProxy })

  // 浏览器只见过门卫地址，拿不到宿主打印在终端里的一次性启动令牌。
  // 门卫在「已登录用户的首页导航」上代跑令牌交换：宿主回 303 + Set-Cookie，
  // 原样透传给浏览器保存，之后所有 /api 与 WS 请求自带会话。
  // 令牌只出现在门卫→宿主这一跳的请求行上，不进入任何下发给浏览器的内容。
  let path = req.url
  let retryOn401 = false
  if (dshAuth && isIndexNavigation(req)) {
    if (hasCookieNamed(headers.cookie, dshAuth.cookieName)) {
      // 浏览器自认为已有会话：先原样透传；宿主判 401（Cookie 过期、签名密钥变更）
      // 时剥掉它重跑一次交换，避免远端用户被 401 墙困住只能清 Cookie。
      retryOn401 = true
    } else {
      path = withLaunchToken(req.url, dshAuth.token)
    }
  }
  attempt(path, headers, retryOn401)

  function attempt(attemptPath, attemptHeaders, mayRetry) {
    const upstream = http.request({
      host: targetHost,
      port: targetPort,
      method: req.method,
      path: attemptPath,
      headers: attemptHeaders,
      agent: false,
    }, (upRes) => {
      if (mayRetry && upRes.statusCode === 401) {
        upRes.resume() // 丢弃宿主 401 正文，改走令牌交换
        attempt(
          withLaunchToken(req.url, dshAuth.token),
          { ...attemptHeaders, cookie: withoutCookie(attemptHeaders.cookie, dshAuth.cookieName) },
          false,
        )
        return
      }
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
          const outHeaders = stripHopByHop(upRes.headers)
          let html = Buffer.concat(chunks).toString('utf8')
          // 宿主可能按 Accept-Encoding 返回 gzip/br 压缩的 HTML（0.1.2-alpha.3 实测）：
          // 注入前必须先解压，且响应的 content-encoding 头必须删除——否则浏览器按压缩
          // 解码注入后的明文 → ERR_CONTENT_DECODING_FAILED。解压失败按原样发送（安全兜底）。
          const enc = String(outHeaders['content-encoding'] ?? '').trim().toLowerCase()
          if (enc && enc !== 'identity') {
            try {
              const buf = Buffer.concat(chunks)
              const raw = enc === 'br'
                ? zlib.brotliDecompressSync(buf)
                : enc === 'gzip' || enc === 'x-gzip'
                  ? zlib.gunzipSync(buf)
                  : enc === 'deflate'
                    ? zlib.inflateSync(buf)
                    : null
              if (raw) {
                html = raw.toString('utf8')
                delete outHeaders['content-encoding']
              }
            } catch (err) {
              // 解压失败：保留原编码原样透传（不注入），避免二次破坏
              res.writeHead(upRes.statusCode ?? 502, outHeaders)
              upRes.unpipe()
              res.end(Buffer.concat(chunks))
              return
            }
          }
          const extraTags = (clientLoopbackTrust ? LOOPBACK_PATCH_TAG : '') + (settingsDownload ? SETTINGS_DOWNLOAD_TAG : '')
          const injected = injectTags(html, extraTags)
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

  /**
   * 上游用普通 HTTP 响应（非 101）拒绝升级时（403/404/401 等），把状态行与响应头
   * 原样回给浏览器再拆除两端。缺了这条，响应落到 http.request 上没人消费，
   * 浏览器侧会一直挂在"连接中"直到超时（实测 40s 无任何字节且不关闭）。
   */
  upstream.on('response', (upRes) => {
    upstream.setTimeout(0)
    if (socket.destroyed) {
      upRes.resume()
      return
    }
    upRes.resume() // 升级被拒时正文无意义，排空后即拆
    const raw = upRes.rawHeaders ?? []
    let response = `HTTP/1.1 ${upRes.statusCode ?? 502} ${upRes.statusMessage ?? ''}\r\n`
    for (let i = 0; i + 1 < raw.length; i += 2) {
      const name = String(raw[i]).toLowerCase()
      if (HOP_BY_HOP.has(name) || name === 'content-length' || name === 'content-encoding') continue
      response += `${raw[i]}: ${raw[i + 1]}\r\n`
    }
    response += 'Content-Length: 0\r\nConnection: close\r\n\r\n'
    socket.write(response)
    socket.end()
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
