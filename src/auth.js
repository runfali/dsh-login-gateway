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

const RECORD_TTL_MS = 30 * 60_000

/**
 * 登录失败限速：IP 与用户名两个维度独立计数，任一达到上限即锁定。
 * 防分布式攻击：代理池打 /login 时每 IP 次数少，但同一用户名跨 IP 累计仍会锁定。
 */
export class LoginLimiter {
  constructor(maxAttempts, lockMs, recordTtlMs = RECORD_TTL_MS) {
    this.maxAttempts = maxAttempts
    this.lockMs = lockMs
    this.recordTtlMs = recordTtlMs
    this.records = new Map() // ip -> { failures, lockedUntil, lastSeen }
    this.usernameRecords = new Map() // username -> { failures, lockedUntil, lastSeen }
  }

  _locked(map, key) {
    const rec = map.get(key)
    if (!rec) return false
    if (rec.lockedUntil && rec.lockedUntil > Date.now()) return true
    if (rec.lockedUntil) map.delete(key)
    return false
  }

  /** 返回锁定的维度：'ip' | 'username' | 'both' | null（不传 username 时只查 IP）。 */
  lockedBy(ip, username) {
    const ipLocked = this._locked(this.records, ip)
    const userLocked = username ? this._locked(this.usernameRecords, username) : false
    if (ipLocked && userLocked) return 'both'
    if (ipLocked) return 'ip'
    if (userLocked) return 'username'
    return null
  }

  /** 任一维度锁定即锁定。 */
  isLocked(ip, username) {
    return this.lockedBy(ip, username) !== null
  }

  _recordFail(map, key, now) {
    let rec = map.get(key)
    if (!rec || (rec.lockedUntil && rec.lockedUntil <= now)) {
      rec = { failures: 0, lockedUntil: 0, lastSeen: now }
      map.set(key, rec)
    }
    rec.lastSeen = now
    rec.failures += 1
    if (rec.failures >= this.maxAttempts) {
      rec.lockedUntil = now + this.lockMs
      rec.failures = 0
      return 0
    }
    return this.maxAttempts - rec.failures
  }

  /** 记录一次失败（IP 必记；提供 username 时用户名维度也记），返回剩余可尝试次数（<=0 表示已锁定）。 */
  recordFailure(ip, username) {
    const now = Date.now()
    let remaining = this._recordFail(this.records, ip, now)
    if (username) {
      remaining = Math.min(remaining, this._recordFail(this.usernameRecords, username, now))
    }
    return remaining
  }

  /** 登录成功后清除记录（IP 必清；提供 username 时用户名维度也清）。 */
  reset(ip, username) {
    this.records.delete(ip)
    if (username) this.usernameRecords.delete(username)
  }

  /** 清理过期记录：未锁定且超过 TTL 的，或锁定已过期的，防止内存膨胀。 */
  sweep() {
    const now = Date.now()
    for (const map of [this.records, this.usernameRecords]) {
      for (const [key, rec] of map) {
        if (rec.lockedUntil ? rec.lockedUntil <= now : now - rec.lastSeen > this.recordTtlMs) {
          map.delete(key)
        }
      }
    }
  }
}
