/**
 * dsh 0.1.2-alpha.1+ 浏览器鉴权适配测试。
 *
 * 该版本起，改 Host/Origin/Sec-Fetch-Site 三头只够过信任围栏（403），
 * 首页与全部 /api 请求还必须带宿主签发的 dsh-auth-* 会话 Cookie（否则 401）。
 * 浏览器只见过门卫地址，拿不到宿主打印在终端里的一次性启动令牌，
 * 因此由门卫在「已登录用户的首页导航」上代跑令牌交换。
 *
 * 这里用一个复刻 BrowserAuth 语义的假上游（token 交换 → 303 + Set-Cookie，
 * 之后按 Cookie 判定）验证门卫的交换、自愈与不泄漏行为。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import { dshAuthCookieName, withLaunchToken } from '../src/proxy.js'
import { startGateway, startUpstream, request, login, cookieOf } from './helpers.js'

const LAUNCH_TOKEN = 'mu23Dv2buIBHutvE4b3t-K5pg4uWOhreWOcfhdonpvE'
const FRESH = 'v1.fresh-from-token-exchange'
const INDEX_HTML = '<html><head><title>dsh</title></head><body>app</body></html>'

/** 复刻宿主 BrowserAuth 判定：pathname '/' + 正确 token 才签发会话；其余按 Cookie。 */
function fakeDshHandler(state) {
  return (req, res) => {
    const u = new URL(req.url ?? '/', 'http://local')
    const cname = dshAuthCookieName(req.headers.host)
    const cookie = String(req.headers.cookie ?? '')
    const hasSession = new RegExp(`(?:^|;\\s*)${cname}=${FRESH}(?:;|$)`).test(cookie)
    state.seen.push({ method: req.method, url: req.url, cookie })
    if (req.method === 'GET' && u.pathname === '/' && u.searchParams.get('token') === LAUNCH_TOKEN) {
      res.writeHead(303, {
        'cache-control': 'no-store',
        location: '/',
        'set-cookie': `${cname}=${FRESH}; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict`,
      })
      return res.end()
    }
    if (!hasSession) {
      res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
      return res.end('dsh web authentication required')
    }
    if (u.pathname === '/' || u.pathname === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      return res.end(INDEX_HTML)
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end('{"ok":true}')
  }
}

/** 起「假 dsh 上游 + 门卫」一对，并完成门卫登录，返回浏览器侧的门卫会话 Cookie。 */
async function start({ connection = null } = {}) {
  const state = { seen: [] }
  const up = await startUpstream(fakeDshHandler(state))
  const gw = await startGateway(
    { targetHost: '127.0.0.1', targetPort: up.port },
    true,
    connection ? { connection } : {},
  )
  return {
    gw,
    up,
    state,
    jar: cookieOf(await login(gw.port)),
    cname: dshAuthCookieName(`127.0.0.1:${up.port}`),
  }
}

const stopAll = async ({ gw, up }) => {
  gw.stop()
  await up.close()
}

// ---------- 纯函数 ----------

test('dshAuthCookieName 与宿主 BrowserAuth 的命名逐字一致（真实抓包向量）', () => {
  // 取自 dsh 0.1.2-alpha.3 实跑：GET http://127.0.0.1:3090/?token=… 的 Set-Cookie 名
  assert.equal(
    dshAuthCookieName('127.0.0.1:3090'),
    'dsh-auth-4b6qQ-Y94Wo8ht4uQsOr6Rc6e47Y7zHxdRsr_25sj5o',
  )
})

test('withLaunchToken 追加 token 且保留既有查询串', () => {
  assert.equal(withLaunchToken('/', 'T'), '/?token=T')
  assert.equal(withLaunchToken('/?a=1', 'T'), '/?a=1&token=T')
  // 已带 token 时不重复追加（URLSearchParams.set 语义）
  assert.equal(withLaunchToken('/?token=old', 'T'), '/?token=T')
})

// ---------- 交换链路 ----------

test('宿主无 authenticatedUrl（≤0.1.1）时行为不变：原样透传，不注入 token', async () => {
  const t = await start({ connection: {} })
  try {
    const home = await request(t.gw.port, 'GET', '/', { headers: { cookie: t.jar } })
    // dshAuth=null → 门卫完全不插手：路径与 Cookie 原样透传，宿主按老样子判 401
    assert.equal(home.status, 401)
    assert.equal(t.state.seen.length, 1)
    assert.equal(t.state.seen[0].url, '/')
  } finally {
    await stopAll(t)
  }
})

test('浏览器无宿主会话 Cookie 时，门卫在首页导航上代跑令牌交换', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const home = await request(t.gw.port, 'GET', '/', { headers: { cookie: t.jar } })
    assert.equal(home.status, 303)
    assert.equal(home.headers.location, '/')
    assert.deepEqual(t.state.seen, [{ method: 'GET', url: `/?token=${LAUNCH_TOKEN}`, cookie: t.jar }])
    // 交换结果原样下发给浏览器保存
    assert.ok(home.headers['set-cookie']?.[0]?.startsWith(`${t.cname}=`))
  } finally {
    await stopAll(t)
  }
})

test('启动令牌只出现在门卫→宿主这一跳，绝不下发给浏览器', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const home = await request(t.gw.port, 'GET', '/', { headers: { cookie: t.jar } })
    assert.ok(!home.body.includes(LAUNCH_TOKEN))
    assert.ok(!JSON.stringify(home.rawHeaders ?? home.headers).includes(LAUNCH_TOKEN))
    // 门卫自产页面同样不含令牌
    const page = await request(t.gw.port, 'GET', '/')
    assert.ok(!page.body.includes(LAUNCH_TOKEN))
  } finally {
    await stopAll(t)
  }
})

test('浏览器已持有效会话 Cookie 时不重复交换，首页正常透传', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const home = await request(t.gw.port, 'GET', '/', {
      headers: { cookie: `${t.jar}; ${t.cname}=${FRESH}` },
    })
    assert.equal(home.status, 200)
    assert.match(home.body, /<body>app<\/body>/)
    assert.equal(t.state.seen.length, 1)
    assert.equal(t.state.seen[0].url, '/')
  } finally {
    await stopAll(t)
  }
})

test('会话 Cookie 失效时自愈：401 后剥掉坏 Cookie 重跑交换，不再要求用户手动清理', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const home = await request(t.gw.port, 'GET', '/', {
      headers: { cookie: `${t.jar}; ${t.cname}=v1.stale-garbage` },
    })
    assert.equal(home.status, 303)
    assert.ok(home.headers['set-cookie']?.[0]?.startsWith(`${t.cname}=`))
    // 第一次原样透传（带坏 Cookie），第二次才交换（坏 Cookie 已剥除）
    assert.equal(t.state.seen.length, 2)
    assert.equal(t.state.seen[0].url, '/')
    assert.match(t.state.seen[0].cookie, /v1\.stale-garbage/)
    assert.equal(t.state.seen[1].url, `/?token=${LAUNCH_TOKEN}`)
    assert.ok(!t.state.seen[1].cookie.includes('stale-garbage'))
  } finally {
    await stopAll(t)
  }
})

test('非首页路径一律不掺令牌：/api 与深链原样透传', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const api = await request(t.gw.port, 'POST', '/api/sessions/list', {
      headers: { cookie: `${t.jar}; ${t.cname}=${FRESH}`, 'content-type': 'application/json' },
      body: '{}',
    })
    assert.equal(api.status, 200)
    assert.equal(t.state.seen.at(-1).url, '/api/sessions/list')

    const deep = await request(t.gw.port, 'GET', '/session/abc', { headers: { cookie: t.jar } })
    assert.equal(deep.status, 401) // 宿主判 401，门卫不改路径也不重试
    assert.equal(t.state.seen.at(-1).url, '/session/abc')
  } finally {
    await stopAll(t)
  }
})

test('未通过门卫登录的浏览器拿不到令牌交换（闸门仍在最前）', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const anon = await request(t.gw.port, 'GET', '/')
    assert.equal(anon.status, 200)
    assert.match(anon.body, /id="login-form"/) // 门卫自己的登录页，不是 dsh
    assert.ok(!t.state.seen.some((s) => s.url.includes('token=')))
  } finally {
    await stopAll(t)
  }
})

test('登出门卫时一并吊销宿主会话 Cookie（共享浏览器不继承上一人的 dsh 会话）', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const out = await request(t.gw.port, 'POST', '/logout', { headers: { cookie: `${t.jar}; ${t.cname}=${FRESH}` } })
    assert.equal(out.status, 302)
    const setc = out.headers['set-cookie'] ?? []
    assert.ok(setc.some((c) => c.startsWith('dsh_gw_session=;') && /Max-Age=0/.test(c)))
    const dsh = setc.find((c) => c.startsWith(`${t.cname}=`))
    assert.ok(dsh, '应带宿主会话 Cookie 的吊销指令')
    assert.match(dsh, /=;\s*Max-Age=0/)
    // 属性须与 dsh 自己签发的那份对齐：它不带 Secure，加了 Secure 就删不掉
    assert.ok(!/Secure/.test(dsh))
  } finally {
    await stopAll(t)
  }
})

test('带请求体的首页请求不参与交换（无法重放正文，保持原样）', async () => {
  const t = await start({ connection: { authenticatedUrl: (b) => `${b}/?token=${LAUNCH_TOKEN}` } })
  try {
    const post = await request(t.gw.port, 'POST', '/', {
      headers: { cookie: t.jar, 'content-type': 'application/json', 'content-length': '2' },
      body: '{}',
    })
    assert.equal(post.status, 401)
    assert.equal(t.state.seen.at(-1).url, '/')
  } finally {
    await stopAll(t)
  }
})
