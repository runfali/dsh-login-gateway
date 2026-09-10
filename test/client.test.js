/**
 * lib/client.js（浏览器端 client bundle）行为测试。
 *
 * 用假 `window.__ModuleLoader__` 捕获注册、再以假 cordis ctx 驱动 apply，
 * 覆盖 0.1.5-rc.1 新引入的 `remote.\$host.hostFacts` 缓存修正。
 * 这套桩忠实复刻宿主真实形状（见各用例注释里的源码出处），避免"桩比真实宽松 → 假绿"。
 */

import test from 'node:test'
import assert from 'node:assert/strict'

/**
 * 载入 client bundle 并返回其 exports。
 * bundle 顶层直接调用 `window.__ModuleLoader__.load(...)`，所以必须先备好全局。
 */
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
    // 每次都要拿到全新的模块实例（bundle 有顶层副作用），故带 query 破坏缓存
    await import(`../lib/client.js?case=${Math.random()}`)
  } finally {
    globalThis.window = prevWindow
  }
  assert.ok(registration, 'client bundle 必须调用 window.__ModuleLoader__.load 注册自己')
  assert.equal(registration.id, 'dsh-login-gateway', '注册 id 必须等于包名')
  return registration.factory(() => {
    throw new Error('本 bundle 不应 require 任何外部模块')
  })
}

/** 造一个最小 cordis ctx：ctx.get(名字, 可选) 与直接属性两种取法都要支持。 */
function makeClientCtx(services) {
  return {
    get: (name, _optional) => services[name],
    ...services,
  }
}

test('client bundle 注册形状：id=包名、apply 同步、注入 connection', async () => {
  const exports = await loadClientBundle()
  assert.equal(typeof exports.apply, 'function')
  assert.equal(exports.apply.constructor.name, 'Function') // 非 async
  assert.deepEqual(exports.inject, ['connection'])
})

test('经门卫访问：把 connection.isLoopback 修正为 true（设置持久化的总开关）', async () => {
  const exports = await loadClientBundle()
  const conn = { isLoopback: false } // 外部 IP 访问时宿主算出的真实值
  exports.apply(makeClientCtx({ connection: conn }))
  assert.equal(conn.isLoopback, true)
})

test('修正 remote.$host.hostFacts 缓存（0.1.5 起 settings 走 $host，且该值被缓存）', async () => {
  const exports = await loadClientBundle()
  const conn = { isLoopback: false }
  // 忠实复刻 dsh-api-gateway 的 ClientRemoteService：
  //   get $host() { if (hostFacts===undefined || hostFacts.home!==home) hostFacts = {home, isLoopback: this.connection.isLoopback}; return hostFacts }
  const remote = {
    hostFacts: { home: '/root', isLoopback: false }, // 在我们修正之前已被读过 → 缓存停在 false
  }
  exports.apply(makeClientCtx({ connection: conn, remote }))
  assert.equal(conn.isLoopback, true)
  assert.equal(remote.hostFacts.isLoopback, true, '缓存不修正则 ui-settings 仍判非 loopback')
})

test('已正确时不做多余写入（幂等，避免每次 boot 都抖动）', async () => {
  const exports = await loadClientBundle()
  const conn = { isLoopback: true }
  const facts = { home: '/root', isLoopback: true }
  const remote = { hostFacts: facts }
  exports.apply(makeClientCtx({ connection: conn, remote }))
  assert.equal(conn.isLoopback, true)
  assert.equal(remote.hostFacts, facts, '对象应原样保留')
})

test('兜底翻 persistence：scope 与 mirror 两处一起改（0.1.2+ 起 binder 不回读 connection）', async () => {
  const exports = await loadClientBundle()
  let loaded = false
  const mirror = {
    persistence: 'memory',
    store: {
      value: { status: 'unavailable', view: { a: 1 }, error: { message: 'x' } },
      set(next) {
        this.value = next
      },
    },
    getSnapshot() {
      return this.store.value
    },
    load() {
      loaded = true
    },
  }
  const scope = { persistence: 'memory', mirror }
  exports.apply(makeClientCtx({ connection: { isLoopback: false }, settingsScope: scope }))
  assert.equal(scope.persistence, 'host')
  assert.equal(mirror.persistence, 'host')
  assert.equal(mirror.store.value.status, 'idle', '快照需置回 idle 等待 load 落地')
  assert.equal(mirror.store.value.view.a, 1, '原有 view 必须保留')
  assert.equal(mirror.store.value.error, null)
  assert.equal(loaded, true, '翻转后应立即触发一次 load')
})

test('依赖缺失/形状异常时静默失败，绝不抛出影响 dsh boot', async () => {
  const exports = await loadClientBundle()
  const cases = [
    {}, // 连 connection 都没有
    { connection: null },
    { connection: { isLoopback: false }, remote: { hostFacts: null } }, // hostFacts 为 null
    { connection: { isLoopback: false }, settingsScope: { persistence: 'memory' } }, // scope 无 mirror
    { connection: { isLoopback: false }, settingsScope: { persistence: 'memory', mirror: { persistence: 'memory' } } }, // mirror 无 store/load
  ]
  for (const services of cases) {
    assert.doesNotThrow(() => exports.apply(makeClientCtx(services)), JSON.stringify(services))
  }
})
