/**
 * dsh 0.1.7-rc.1 适配回归（本仓库 0.1.7 适配轮）。
 *
 * 0.1.7-rc.1 与 0.1.5-rc.1 的宿主鉴权契约逐字一致（BrowserAuth / authorizeIndex /
 * sessionCookie 属性 / 401 文案），本文件把 0.1.7 的形状固化为回归，防止未来
 * 「以为 0.1.7 有漂移」或反向的意外破坏：
 * - 401 文案：dsh web authentication required; reopen the URL printed by dsh web.
 * - Cookie 属性仍为 Max-Age/Path/Expires/HttpOnly/SameSite=Strict（无 Secure）
 * - 0.1.7 起 dsh-client-ui-settings 的宿主服务名从 settingsScope 改为 configForms：
 *   client bundle 的兜底修复必须能在 configForms 命中并翻转 persistence。
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { dshAuthCookieName } from '../src/proxy.js'
import { startGateway, startUpstream, request, login, cookieOf } from './helpers.js'

const LAUNCH_TOKEN = 'launch-token-017'
const COOKIE_VALUE = 'v1.signed-payload-017'
/** 0.1.5/0.1.7 的 401 文案（一致）。 */
const UNAUTHORIZED_017 = 'dsh web authentication required; reopen the URL printed by dsh web.\n'

/** 逐字复刻 0.1.7 BrowserAuth 行为（与 0.1.5 相同形状）。 */
function browserAuth017(state) {
  return (req, res) => {
    const url = new URL(req.url ?? '/', 'http://dsh.invalid')
    const authority = new URL(`http://${req.headers.host}`).host
    const name = dshAuthCookieName(authority)
    const cookie = String(req.headers.cookie ?? '')
    const hasSession = cookie.includes(`${name}=${COOKIE_VALUE}`)
    state.seen.push({ url: req.url, method: req.method, host: req.headers.host, cookie: req.headers.cookie })

    const tokens = url.searchParams.getAll('token')
    if (tokens.length > 0) {
      if (req.method === 'GET' && url.pathname === '/' && tokens.length === 1 && tokens[0] === LAUNCH_TOKEN) {
        res.writeHead(303, {
          'cache-control': 'no-store',
          location: './',
          'referrer-policy': 'no-referrer',
          'set-cookie': `${name}=${COOKIE_VALUE}; Max-Age=2592000; Path=/; Expires=${new Date(Date.now() + 2592000000).toUTCString()}; HttpOnly; SameSite=Strict`,
        })
        return res.end()
      }
      if (req.method === 'GET' && url.pathname === '/' && hasSession) {
        res.writeHead(303, { 'cache-control': 'no-store', location: './', 'referrer-policy': 'no-referrer' })
        return res.end()
      }
      res.writeHead(401, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' })
      return res.end(req.method === 'HEAD' ? undefined : UNAUTHORIZED_017)
    }
    if (hasSession) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      return res.end('<html><head><base href="./"></head><body>017 app</body></html>')
    }
    res.writeHead(401, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' })
    res.end(req.method === 'HEAD' ? undefined : UNAUTHORIZED_017)
  }
}

async function start017() {
  const state = { seen: [] }
  const up = await startUpstream(browserAuth017(state))
  const gw = await startGateway({ targetPort: up.port }, true, {
    connection: { authenticatedUrl: (base) => `${base}/?token=${LAUNCH_TOKEN}` },
  })
  return { gw, up, state, jar: cookieOf(await login(gw.port)), cname: dshAuthCookieName(`127.0.0.1:${up.port}`) }
}

const stop = async ({ gw, up }) => {
  gw.stop()
  await up.close()
}

test('0.1.7：无宿主 Cookie 时门卫代跑令牌交换，303 与 Cookie 原样下发', async () => {
  const t = await start017()
  try {
    const home = await request(t.gw.port, 'GET', '/', { headers: { cookie: t.jar } })
    assert.equal(home.status, 303)
    assert.ok(['/', './'].includes(home.headers.location))
    assert.equal(t.state.seen.at(-1).url, `/?token=${LAUNCH_TOKEN}`)
    const setCookie = home.headers['set-cookie'][0]
    assert.ok(setCookie.startsWith(`${t.cname}=`))
    assert.match(setCookie, /HttpOnly/)
    assert.match(setCookie, /SameSite=Strict/)
    assert.ok(!/Secure/.test(setCookie), '0.1.7 宿主 Cookie 不带 Secure，门卫登出才删得掉')
  } finally {
    await stop(t)
  }
})

test('0.1.7：已持有效宿主 Cookie 时不再重复交换，首页原样透传', async () => {
  const t = await start017()
  try {
    const home = await request(t.gw.port, 'GET', '/', {
      headers: { cookie: `${t.jar}; ${t.cname}=${COOKIE_VALUE}` },
    })
    assert.equal(home.status, 200)
    assert.match(home.body, /017 app/)
    assert.equal(t.state.seen.length, 1)
    assert.equal(t.state.seen[0].url, '/')
  } finally {
    await stop(t)
  }
})

test('0.1.7：宿主 401 时门卫自愈重试交换（剥坏 Cookie 重跑）', async () => {
  const t = await start017()
  try {
    const home = await request(t.gw.port, 'GET', '/', {
      headers: { cookie: `${t.jar}; ${t.cname}=v1.stale` },
    })
    assert.equal(home.status, 303)
    assert.equal(t.state.seen.length, 2)
    assert.match(t.state.seen[0].cookie ?? '', /v1\.stale/)
    assert.equal(t.state.seen[1].url, `/?token=${LAUNCH_TOKEN}`)
    assert.ok(!/v1\.stale/.test(t.state.seen[1].cookie ?? ''))
  } finally {
    await stop(t)
  }
})

test('0.1.7：令牌绝不下发给浏览器（正文与响应头都要干净）', async () => {
  const t = await start017()
  try {
    const home = await request(t.gw.port, 'GET', '/', { headers: { cookie: t.jar } })
    assert.ok(!home.body.includes(LAUNCH_TOKEN))
    assert.ok(!JSON.stringify(home.rawHeaders ?? home.headers).includes(LAUNCH_TOKEN))
  } finally {
    await stop(t)
  }
})

test('0.1.7：登出同时吊销宿主 Cookie（属性对齐 0.1.7 sessionCookie）', async () => {
  const t = await start017()
  try {
    const out = await request(t.gw.port, 'POST', '/logout', {
      headers: { cookie: `${t.jar}; ${t.cname}=${COOKIE_VALUE}` },
    })
    assert.equal(out.status, 302)
    const cookies = out.headers['set-cookie'] ?? []
    assert.ok(cookies.some((c) => c.startsWith('dsh_gw_session=;')))
    const dsh = cookies.find((c) => c.startsWith(`${t.cname}=`))
    assert.ok(dsh, '必须带宿主 Cookie 的吊销指令')
    assert.match(dsh, /Max-Age=0/)
    assert.ok(!/Secure/.test(dsh), '属性需与 0.1.7 sessionCookie 对齐（它不带 Secure）')
  } finally {
    await stop(t)
  }
})

/** 载入 client bundle（与 test/client.test.js 同款桩）。 */
async function loadClientBundle() {
  let registration
  const prevWindow = globalThis.window
  globalThis.window = {
    __ModuleLoader__: {
      load(reg) {
        registration = reg
      },
    },
  }
  try {
    await import(`../lib/client.js?case=${Math.random()}`)
  } finally {
    globalThis.window = prevWindow
  }
  return registration.factory(() => {
    throw new Error('本 bundle 不应 require 任何外部模块')
  })
}

function makeClientCtx(services) {
  return { get: (name) => services[name], ...services }
}

test('0.1.7 client 兜底：configForms 服务（0.1.7 新宿主服务名）persistence/memory 被翻转并触发 reload', async () => {
  const exports = await loadClientBundle()
  let storeSet = 0
  let mirrorLoad = 0
  let snap = { status: 'unavailable', view: { namespaces: [] }, error: null }
  const mirror = {
    persistence: 'memory',
    store: {
      getSnapshot: () => snap,
      set: (next) => { storeSet += 1; snap = next },
    },
    getSnapshot() { return snap },
    load() { mirrorLoad += 1 },
  }
  const configForms = { persistence: 'memory', mirror }
  const connection = { isLoopback: false }
  const remote = { hostFacts: { home: undefined, isLoopback: false } }

  exports.apply(makeClientCtx({ connection, remote, configForms }))

  // 0.1.7 命中 configForms：persistence 翻转 + mirror 翻转 + 快照复位 + load()
  assert.equal(configForms.persistence, 'host')
  assert.equal(mirror.persistence, 'host')
  assert.equal(storeSet, 1)
  assert.equal(snap.status, 'idle', '快照需置回 idle 等待 load 落地')
  assert.deepEqual(snap.view, { namespaces: [] }, '原有 view 必须保留')
  assert.equal(snap.error, null)
  assert.equal(mirrorLoad, 1, '翻转后应立即触发一次 load')
  // 同一遍里把 connection / hostFacts 也修了
  assert.equal(connection.isLoopback, true)
  assert.equal(remote.hostFacts.isLoopback, true)
})

test('0.1.7 client 兜底：0.1.5 的 settingsScope 服务名同时保留兼容（旧宿主不受影响）', async () => {
  const exports = await loadClientBundle()
  let loaded = false
  const mirror = {
    persistence: 'memory',
    store: {
      value: { status: 'unavailable', view: { a: 1 }, error: { message: 'x' } },
      set(next) { this.value = next },
    },
    getSnapshot() { return this.store.value },
    load() { loaded = true },
  }
  const scope = { persistence: 'memory', mirror }
  exports.apply(makeClientCtx({ connection: { isLoopback: false }, settingsScope: scope }))
  assert.equal(scope.persistence, 'host')
  assert.equal(mirror.persistence, 'host')
  assert.equal(mirror.store.value.status, 'idle')
  assert.equal(mirror.store.value.error, null)
  assert.equal(loaded, true)
})

test('0.1.7 client 兜底：两服务都缺失（0.1.7 正常时序）时静默跳过', async () => {
  const exports = await loadClientBundle()
  const cases = [
    {},
    { connection: null },
    { connection: { isLoopback: false }, remote: { hostFacts: null } },
    { connection: { isLoopback: false }, configForms: { persistence: 'memory' } }, // 服务在但字段缺失
    { connection: { isLoopback: false }, configForms: { persistence: 'memory', mirror: { persistence: 'memory' } } }, // mirror 无 store/load
  ]
  for (const services of cases) {
    assert.doesNotThrow(() => exports.apply(makeClientCtx(services)), JSON.stringify(services))
  }
})
