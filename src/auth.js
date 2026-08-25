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

// 预计算的哑哈希：用户名不存在时也执行一次等价 scrypt 计算，
// 抹平「账号存在与否」的响应时序差，防止用户名枚举。
const DUMMY_HASH = hashPassword('dsh-login-gateway-dummy-verify')

/** 假校验：仅消耗等价 CPU 时间，结果无意义。 */
export function fakeVerify(password) {
  try {
    verifyPassword(password, DUMMY_HASH)
  } catch {
    /* 忽略 */
  }
}

/**
 * 恒定时间的字符串相等比较（用于一次性令牌等秘密值）。
 * 长度不同时也执行一次同长比较，避免泄漏长度差信息。
 */
export function safeEqualStr(a, b) {
  const ba = Buffer.from(String(a ?? ''), 'utf8')
  const bb = Buffer.from(String(b ?? ''), 'utf8')
  if (ba.length !== bb.length) {
    timingSafeEqual(ba, ba)
    return false
  }
  return timingSafeEqual(ba, bb)
}

/**
 * 会话存储：内存 Map，token -> { username, expiresAt }。
 * maxSessions 上限防止已认证方反复登录把内存刷爆（逐出最旧会话）。
 */
export class SessionStore {
  constructor(ttlMs, maxSessions = 1000) {
    this.ttlMs = ttlMs
    this.maxSessions = Math.max(1, Number(maxSessions) || 1000)
    this.sessions = new Map()
  }

  create(username) {
    if (this.sessions.size >= this.maxSessions) {
      // Map 保持插入序：TTL 相同 ⇒ 最先插入即最先过期，逐出最旧
      const oldest = this.sessions.keys().next().value
      if (oldest !== undefined) this.sessions.delete(oldest)
    }
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
 * maxKeys 上限防止伪造海量 IP/用户名把记录表刷爆（优先清过期，再逐出最旧）。
 */
export class LoginLimiter {
  constructor(maxAttempts, lockMs, recordTtlMs = RECORD_TTL_MS, maxKeys = 10_000) {
    this.maxAttempts = maxAttempts
    this.lockMs = lockMs
    this.recordTtlMs = recordTtlMs
    this.maxKeys = Math.max(1, Number(maxKeys) || 10_000)
    this.records = new Map() // ip -> { failures, lockedUntil, lastSeen }
    this.usernameRecords = new Map() // username -> { failures, lockedUntil, lastSeen }
  }

  /** 容量保障：先清本表过期记录；仍满则逐出最旧一条（O(n)，仅在满时发生）。 */
  _ensureCapacity(map, now) {
    if (map.size < this.maxKeys) return
    for (const [k, r] of map) {
      const expired = r.lockedUntil ? r.lockedUntil <= now : now - r.lastSeen > this.recordTtlMs
      if (expired) map.delete(k)
      if (map.size < this.maxKeys) return
    }
    let oldestKey = null
    let oldestSeen = Infinity
    for (const [k, r] of map) {
      if (r.lastSeen < oldestSeen) {
        oldestSeen = r.lastSeen
        oldestKey = k
      }
    }
    if (oldestKey !== null) map.delete(oldestKey)
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
    if (!rec) {
      this._ensureCapacity(map, now)
      rec = { failures: 0, lockedUntil: 0, lastSeen: now }
      map.set(key, rec)
    } else if (rec.lockedUntil && rec.lockedUntil <= now) {
      // 锁已过期：重新计数
      rec.failures = 0
      rec.lockedUntil = 0
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
