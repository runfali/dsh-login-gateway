/**
 * 第六轮（2026-09-10）追加回归：用户名规范化 + 异步校验 + 越界哈希。
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { checkUsername, verifyPasswordAsync, hashPassword } from '../src/auth.js'
import { startGateway, request } from './helpers.js'

test('checkUsername：放行中英文/数字/._-@+，拒绝空白、控制字符与其它标点', () => {
  assert.equal(checkUsername('admin'), null)
  assert.equal(checkUsername('张伟'), null)
  assert.equal(checkUsername('user.name-1_2@example+tag'), null)
  assert.match(checkUsername(' user'), /首尾/)
  assert.match(checkUsername('user name'), /空白/)
  assert.match(checkUsername('user\tname'), /空白/)
  assert.match(checkUsername('user\u0000name'), /控制字符/)
  assert.match(checkUsername('user!name'), /只能包含/)
  assert.match(checkUsername('user/../name'), /只能包含/)
})

test('setup 拒绝不合规用户名（含全角空格与路径分隔符）', async () => {
  // 放宽 setup 失败上限：本用例只验证用户名字符集，不该被 IP 锁定打断
  const gw = await startGateway({ setupMaxAttempts: 50 }, false)
  try {
    const token = gw.logs.find((l) => l.includes('一次性令牌')).match(/令牌：([A-Z0-9-]+)/)[1]
    const setup = (username) =>
      request(gw.port, 'POST', '/setup', {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token, username, password: 'Str0ng!Pass9', password2: 'Str0ng!Pass9' }),
      })
    // 注意：首尾空白在校验前已被 trim（不可见差异不会留存），这里只测"内部"非法字符
    for (const bad of ['a b', 'a!b', 'a/b', 'a\u3000b', 'a\u00a0b']) {
      const res = await setup(bad)
      assert.equal(res.status, 400, `${bad} 应被拒绝`)
    }
    // 合规用户名可正常建号
    const ok = await setup('张伟.01')
    assert.equal(ok.status, 200)
  } finally {
    gw.stop()
  }
})

test('越界/畸形哈希参数不会拖垮校验（上界防御）', async () => {
  const huge = 'scrypt$1073741824$8$1$AAAA$AAAA' // N=2^30，若真跑会 OOM
  assert.equal(await verifyPasswordAsync('x', huge), false)
  assert.equal(await verifyPasswordAsync('x', 'scrypt$16384$8$1$AAAA$'), false) // 空哈希段
  const long = 'scrypt$16384$8$1$AAAA$' + 'A'.repeat(4000)
  assert.equal(await verifyPasswordAsync('x', long), false)
  // 正常哈希仍可校验（参数未变）
  assert.equal(await verifyPasswordAsync('pw', hashPassword('pw')), true)
})
