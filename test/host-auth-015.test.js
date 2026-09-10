/**
 * 宿主浏览器鉴权契约的**跨版本形状**回归（0.1.2-rc.1 / 0.1.5-rc.1）。
 *
 * 两版 `authorizeIndex` 语义逐字一致（GET + pathname '/' + 单 token → 303 + Set-Cookie；
 * 其余按签名 Cookie 判 401），本文件把 0.1.5 的实际形状固化成回归：
 * - 401 文案在 0.1.5 改为 `dsh web authentication required; reopen the URL printed by dsh web.`
 * - Cookie 属性仍为 `Max-Age/Path/HttpOnly/SameSite=Strict`（不带 Secure）→ 门卫登出必须能删
 * - `/index.html` 与 `/` 都会走同一条 index 鉴权（0.1.5 的 frontend-static 另有 <base href> 注入）
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { dshAuthCookieName } from '../src/proxy.js'
import { startGateway, startUpstream, request, login, cookieOf } from './helpers.js'

const LAUNCH_TOKEN = 'launch-token-015'
const COOKIE_VALUE = 'v1.signed-payload-015'
/** 0.1.5 的 401 文案（尾部多了 reopen 提示）。 */
const UNAUTHORIZED_015 = 'dsh web authentication required; reopen the URL printed by dsh web.\n'

/** 逐字复刻 0.1.5 BrowserAuth 行为（含 Cookie 属性与 401 文案）。 */
function browserAuth015(state) {
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
          location: '/',
          'referrer-policy': 'no-referrer',
          // 0.1.5 的 sessionCookie()：无 Secure
          'set-cookie': `${name}=${COOKIE_VALUE}; Max-Age=2592000; Path=/; Expires=${new Date(Date.now() + 2592000000).toUTCString()}; HttpOnly; SameSite=Strict`,
        })
        return res.end()
      }
      if (req.method === 'GET' && url.pathname === '/' && hasSession) {
        res.writeHead(303, { 'cache-control': 'no-store', location: '/', 'referrer-policy': 'no-referrer' })
        return res.end()
      }
      res.writeHead(401, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' })
      return res.end(req.method === 'HEAD' ? undefined : UNAUTHORIZED_015)
    }
    if (hasSession) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      return res.end('<html><head><base href="/"></head><body>015 app</body></html>')
    }
    res.writeHead(401, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' })
    res.end(req.method === 'HEAD' ? undefined : UNAUTHORIZED_015)
  }
}

async function start015() {
  const state = { seen: [] }
  const up = await startUpstream(browserAuth015(state))
  const gw = await startGateway({ targetPort: up.port }, true, {
    connection: { authenticatedUrl: (base) => `${base}/?token=${LAUNCH_TOKEN}` },
  })
  return { gw, up, state, jar: cookieOf(await login(gw.port)), cname: dshAuthCookieName(`127.0.0.1:${up.port}`) }
}

const stop = async ({ gw, up }) => {
  gw.stop()
  await up.close()
}

test('0.1.5：无宿主 Cookie 时门卫代跑令牌交换，303 与 Cookie 原样下发', async () => {
  const t = await start015()
  try {
    const home = await request(t.gw.port, 'GET', '/', { headers: { cookie: t.jar } })
    assert.equal(home.status, 303)
    assert.equal(home.headers.location, '/')
    assert.equal(t.state.seen.at(-1).url, `/?token=${LAUNCH_TOKEN}`)
    const setCookie = home.headers['set-cookie'][0]
    assert.ok(setCookie.startsWith(`${t.cname}=`))
    assert.match(setCookie, /HttpOnly/)
    assert.match(setCookie, /SameSite=Strict/)
    assert.ok(!/Secure/.test(setCookie), '0.1.5 宿主 Cookie 不带 Secure，门卫登出才删得掉')
  } finally {
    await stop(t)
  }
})

test('0.1.5：已持有效宿主 Cookie 时不再重复交换，首页原样透传', async () => {
  const t = await start015()
  try {
    const home = await request(t.gw.port, 'GET', '/', {
      headers: { cookie: `${t.jar}; ${t.cname}=${COOKIE_VALUE}` },
    })
    assert.equal(home.status, 200)
    assert.match(home.body, /015 app/)
    assert.equal(t.state.seen.length, 1)
    assert.equal(t.state.seen[0].url, '/')
  } finally {
    await stop(t)
  }
})

test('0.1.5：宿主 401（签名密钥变更/Cookie 过期）时门卫自愈重试交换', async () => {
  const t = await start015()
  try {
    const home = await request(t.gw.port, 'GET', '/', {
      headers: { cookie: `${t.jar}; ${t.cname}=v1.stale` },
    })
    assert.equal(home.status, 303)
    assert.equal(t.state.seen.length, 2)
    assert.equal(t.state.seen[0].url, '/')
    assert.match(t.state.seen[0].cookie ?? '', /v1\.stale/)
    assert.equal(t.state.seen[1].url, `/?token=${LAUNCH_TOKEN}`)
    assert.ok(!/v1\.stale/.test(t.state.seen[1].cookie ?? ''))
  } finally {
    await stop(t)
  }
})

test('0.1.5：令牌绝不下发给浏览器（正文与响应头都要干净）', async () => {
  const t = await start015()
  try {
    const home = await request(t.gw.port, 'GET', '/', { headers: { cookie: t.jar } })
    assert.ok(!home.body.includes(LAUNCH_TOKEN))
    assert.ok(!JSON.stringify(home.rawHeaders ?? home.headers).includes(LAUNCH_TOKEN))
  } finally {
    await stop(t)
  }
})

test('0.1.5：/index.html 直连（新版 frontend-static 同样走 index 鉴权）不被门卫擅自掺令牌', async () => {
  const t = await start015()
  try {
    // 门卫只在 pathname '/' 上代跑交换：/index.html 原样透传，由宿主按 Cookie 裁定
    const res = await request(t.gw.port, 'GET', '/index.html', { headers: { cookie: t.jar } })
    assert.equal(res.status, 401)
    assert.equal(t.state.seen.at(-1).url, '/index.html')
    assert.ok(!t.state.seen.at(-1).url.includes('token='))
  } finally {
    await stop(t)
  }
})

test('0.1.5：宿主 401 文案变化不影响门卫判定（门卫只认状态码）', async () => {
  const t = await start015()
  try {
    // 用失效 Cookie 触发宿主 401，门卫应据状态码重试而非匹配文案
    const res = await request(t.gw.port, 'GET', '/', {
      headers: { cookie: `${t.jar}; ${t.cname}=v1.expired` },
    })
    assert.equal(res.status, 303, '门卫按状态码重试，不依赖 401 正文文案')
  } finally {
    await stop(t)
  }
})

test('0.1.5：登出同时吊销宿主 Cookie（属性对齐新版 sessionCookie）', async () => {
  const t = await start015()
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
    assert.ok(!/Secure/.test(dsh), '属性需与 0.1.5 sessionCookie 对齐（它不带 Secure）')
  } finally {
    await stop(t)
  }
})
