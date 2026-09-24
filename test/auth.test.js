/**
 * auth.js 单元测试：密码哈希、会话存储、登录限速。
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { hashPassword, verifyPassword, verifyPasswordAsync, fakeVerifyAsync, safeEqualStr, checkNewPassword, GlobalAuthThrottle, SessionStore, LoginLimiter } from '../src/auth.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

test('hashPassword 产出自描述 scrypt 格式', () => {
  const h = hashPassword('secret-password')
  assert.match(h, /^scrypt\$16384\$8\$1\$/)
})

test('verifyPassword 正确/错误/篡改/垃圾输入', () => {
  const h = hashPassword('secret-password')
  assert.equal(verifyPassword('secret-password', h), true)
  assert.equal(verifyPassword('wrong-password', h), false)
  // 篡改哈希段首字符（padding 位篡改在 base64 解码后等价，须避开）
  const parts = h.split('$')
  const first = parts[5][0]
  parts[5] = (first === 'A' ? 'B' : 'A') + parts[5].slice(1)
  assert.equal(verifyPassword('secret-password', parts.join('$')), false)
  // 垃圾输入一律 false 而非抛错
  assert.equal(verifyPassword('x', 'garbage'), false)
  assert.equal(verifyPassword('x', 'scrypt$1$1$1$!!!$!!!'), false)
  assert.equal(verifyPassword('x', ''), false)
})

test('同密码不同盐产生不同哈希', () => {
  assert.notEqual(hashPassword('same'), hashPassword('same'))
})

test('SessionStore 创建/读取/删除', async () => {
  const s = new SessionStore(60_000)
  const t = s.create('alice')
  assert.equal(s.get(t).username, 'alice')
  s.delete(t)
  assert.equal(s.get(t), null)
  assert.equal(s.get(''), null)
  assert.equal(s.get(undefined), null)
})

test('SessionStore 过期判定与 sweep', async () => {
  const s = new SessionStore(40)
  const a = s.create('a')
  s.sweep() // 未过期：保留
  assert.ok(s.get(a))
  await sleep(50)
  assert.equal(s.get(a), null) // get 时惰性过期
  const b = s.create('b')
  await sleep(50)
  s.sweep()
  assert.equal(s.get(b), null) // sweep 后彻底清除
})

test('LoginLimiter IP 维度：计满锁定、到期解锁', async () => {
  const l = new LoginLimiter(3, 60)
  assert.equal(l.recordFailure('1.1.1.1'), 2)
  assert.equal(l.recordFailure('1.1.1.1'), 1)
  assert.equal(l.lockedBy('1.1.1.1'), null)
  assert.equal(l.recordFailure('1.1.1.1'), 0) // 第3次触发锁定
  assert.equal(l.lockedBy('1.1.1.1'), 'ip')
  assert.equal(l.isLocked('1.1.1.1'), true)
  await sleep(70)
  assert.equal(l.isLocked('1.1.1.1'), false) // 锁定到期自动解除
})

test('LoginLimiter 用户名维度跨 IP 累计锁定', () => {
  const l = new LoginLimiter(3, 60_000)
  l.recordFailure('1.1.1.1', 'bob')
  l.recordFailure('2.2.2.2', 'bob')
  assert.equal(l.lockedBy('9.9.9.9', 'bob'), null)
  l.recordFailure('3.3.3.3', 'bob') // 第3次（跨IP）触发用户名锁
  assert.equal(l.lockedBy('9.9.9.9', 'bob'), 'username')
  assert.equal(l.isLocked('9.9.9.9'), false) // 新 IP 本身未锁
  assert.equal(l.isLocked('9.9.9.9', 'bob'), true) // 但带用户名即拒
})

test('LoginLimiter reset 清除双维度记录', () => {
  const l = new LoginLimiter(5, 60_000)
  l.recordFailure('1.1.1.1', 'carl')
  l.recordFailure('1.1.1.1', 'carl')
  l.reset('1.1.1.1', 'carl')
  assert.equal(l.lockedBy('1.1.1.1', 'carl'), null)
  // 剩余次数重新从满额起算
  assert.equal(l.recordFailure('1.1.1.1', 'carl'), 4)
})

test('LoginLimiter sweep 清理过期未锁定记录与已到期锁', async () => {
  const l = new LoginLimiter(100, 30, 20) // recordTtl=20ms，便于测试
  l.recordFailure('1.1.1.1', 'dave')
  await sleep(30)
  l.sweep()
  assert.equal(l.lockedBy('1.1.1.1', 'dave'), null)
  // 记录被清后剩余次数回到满额
  assert.equal(l.recordFailure('1.1.1.1', 'dave'), 99)
})

test('fakeVerifyAsync 消耗等价计算且不抛错（反枚举哑校验）', async () => {
  await assert.doesNotReject(() => fakeVerifyAsync('anything'))
})

test('verifyPasswordAsync 与同步版结果一致，且非法哈希不抛', async () => {
  const h = hashPassword('secret-password')
  assert.equal(await verifyPasswordAsync('secret-password', h), true)
  assert.equal(await verifyPasswordAsync('wrong-password', h), false)
  assert.equal(await verifyPasswordAsync('x', 'garbage'), false)
  assert.equal(await verifyPasswordAsync('x', 'scrypt$1$1$1$!!!$!!!'), false)
  // 篡改参数超出安全上界：不抛、不爆内存、直接 false
  assert.equal(await verifyPasswordAsync('x', 'scrypt$1073741824$8$1$AAAA$AAAA'), false)
})

test('verifyPasswordAsync 不阻塞事件循环（scrypt 走线程池）', async () => {
  const h = hashPassword('secret-password')
  let ticks = 0
  const timer = setInterval(() => { ticks += 1 }, 1)
  await Promise.all([verifyPasswordAsync('secret-password', h), verifyPasswordAsync('wrong', h)])
  clearInterval(timer)
  // 同步 scrypt 会独占事件循环（~40ms×2 → 1ms 定时器几乎不可能 tick）。
  // 计时敏感（CI/Windows 负载下 1ms 定时器会合并），阈值放宽到「至少 tick 过一次」，
  // 同步实现仍会以 0 tick 稳定失败。
  assert.ok(ticks >= 1, `事件循环被阻塞，timer tick=${ticks}`)
})

test('GlobalAuthThrottle 窗口计数与重置', () => {
  const t = new GlobalAuthThrottle(3, 60_000)
  assert.equal(t.acquire(1000), true)
  assert.equal(t.acquire(1000), true)
  assert.equal(t.acquire(1000), true)
  assert.equal(t.acquire(1000), false) // 满
  assert.equal(t.acquire(61_000), true) // 新窗口重置
})

test('checkNewPassword 拦截黑名单/纯数字/重复字符，放行正常密码', () => {
  assert.match(checkNewPassword('password123'), /常见/)
  assert.match(checkNewPassword('12345678'), /常见|纯数字/) // 同时命中黑名单与纯数字，任一拒绝即可
  assert.match(checkNewPassword('98765432'), /纯数字/)
  assert.match(checkNewPassword('aaaaaaaa'), /重复/)
  assert.equal(checkNewPassword('Str0ng!Pass9'), null)
  assert.equal(checkNewPassword('正确的中文密码九个字'), null)
})

test('safeEqualStr 恒定时间语义：相等/不等/长度不同/非字符串', () => {
  const secret = 'ABCD-EFGH-IJKL'
  assert.equal(safeEqualStr(secret, secret), true)
  assert.equal(safeEqualStr(secret, 'ABCD-EFGH-IJKM'), false)
  assert.equal(safeEqualStr(secret, 'short'), false) // 长度不同不抛错
  assert.equal(safeEqualStr(secret, ''), false)
  assert.equal(safeEqualStr(undefined, secret), false)
  assert.equal(safeEqualStr(null, null), true)
})

test('SessionStore 容量上限逐出最旧会话', () => {
  const s = new SessionStore(60_000, 3)
  const t1 = s.create('a')
  const t2 = s.create('b')
  s.create('c')
  const t4 = s.create('d') // 容量满，逐出 a
  assert.equal(s.get(t1), null)
  assert.ok(s.get(t2))
  assert.ok(s.get(t4))
})

test('LoginLimiter 容量上限优先清过期、再逐出最旧', async () => {
  const l = new LoginLimiter(5, 60_000, 20, 3) // maxKeys=3
  l.recordFailure('1.1.1.1')
  l.recordFailure('2.2.2.2')
  await sleep(30) // 让前两条过期
  l.recordFailure('3.3.3.3') // 满：应先清掉过期的 1/2 而不是逐出
  l.recordFailure('4.4.4.4')
  assert.ok(l.records.has('3.3.3.3'))
  assert.ok(l.records.has('4.4.4.4'))
  assert.ok(!l.records.has('1.1.1.1')) // 过期记录已被容量保障清理
})
