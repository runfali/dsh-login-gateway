/**
 * dsh-login-gateway 认证核心：密码哈希、会话管理、登录限速。
 * 零外部依赖，全部使用 node:crypto 内置实现（scrypt）。
 */

import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

/**
 * 密码哈希格式：scrypt$N$r$p$saltB64$hashB64
 * 自描述，换参数也兼容旧哈希。
 */
export function hashPassword(password) {
  const salt = randomBytes(16)
  const N = 16384
  const r = 8
  const p = 1
  const hash = scryptSync(password, salt, 64, { N, r, p })
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`
}

/** 校验密码与存储哈希是否匹配（恒定时间比较，防时序攻击）。 */
export function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split('$')
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false
    const [, N, r, p, saltB64, hashB64] = parts
    const salt = Buffer.from(saltB64, 'base64')
    const expected = Buffer.from(hashB64, 'base64')
    const actual = scryptSync(password, salt, expected.length, {
      N: Number(N), r: Number(r), p: Number(p),
    })
    return actual.length === expected.length && timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

/** 会话存储：内存 Map，token -> { username, expiresAt }。 */
export class SessionStore {
  constructor(ttlMs) {
    this.ttlMs = ttlMs
    this.sessions = new Map()
  }

  create(username) {
    const token = randomBytes(32).toString('hex')
    this.sessions.set(token, { username, expiresAt: Date.now() + this.ttlMs })
    return token
  }

  /** 返回会话对象，不存在或过期返回 null。 */
  get(token) {
    if (!token) return null
    const s = this.sessions.get(token)
    if (!s) return null
    if (s.expiresAt < Date.now()) {
      this.sessions.delete(token)
      return null
    }
    return s
  }

  delete(token) {
    this.sessions.delete(token)
  }

  /** 清理过期会话，定期调用防止内存增长。 */
  sweep() {
    const now = Date.now()
    for (const [token, s] of this.sessions) {
      if (s.expiresAt < now) this.sessions.delete(token)
    }
  }
}

/** 登录失败限速：同一 IP 连续失败达到上限后锁定一段时间。 */
export class LoginLimiter {
  constructor(maxAttempts, lockMs) {
    this.maxAttempts = maxAttempts
    this.lockMs = lockMs
    this.records = new Map() // ip -> { failures, lockedUntil }
  }

  /** 该 IP 当前是否被锁定。 */
  isLocked(ip) {
    const rec = this.records.get(ip)
    if (!rec) return false
    if (rec.lockedUntil && rec.lockedUntil > Date.now()) return true
    if (rec.lockedUntil) this.records.delete(ip)
    return false
  }

  /** 记录一次失败，返回剩余可尝试次数（<=0 表示已锁定）。 */
  recordFailure(ip) {
    const now = Date.now()
    let rec = this.records.get(ip)
    if (!rec || (rec.lockedUntil && rec.lockedUntil <= now)) {
      rec = { failures: 0, lockedUntil: 0 }
      this.records.set(ip, rec)
    }
    rec.failures += 1
    if (rec.failures >= this.maxAttempts) {
      rec.lockedUntil = now + this.lockMs
      rec.failures = 0
      return 0
    }
    return this.maxAttempts - rec.failures
  }

  /** 登录成功后清除记录。 */
  reset(ip) {
    this.records.delete(ip)
  }
}
