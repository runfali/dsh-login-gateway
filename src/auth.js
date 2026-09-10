/**
 * dsh-login-gateway 认证核心：密码哈希、会话管理、登录限速。
 * 零外部依赖，全部使用 node:crypto 内置实现（scrypt）。
 */

import { createHash, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto'

/**
 * 请求字段的安全取值：只接受字符串（数字按字面量转换），其余一律空串。
 * JSON 里塞 {"password":{"toString":1}} 这类值会让 String() 抛
 * "Cannot convert object to primitive value"，被外层 catch 变成 500——
 * 这是纯粹的输入校验缺失，不该升级成服务端错误。
 */
export function asString(value) {
  if (typeof value === 'string') return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return ''
}

/**
 * 客户端地址规范化：IPv4-mapped IPv6（::ffff:1.2.3.4，Node 在双栈监听下对 IPv4
 * 客户端的常见形态）统一还原成 1.2.3.4，避免同一台主机以两种表示各占一个限速桶。
 */
export function normalizeIp(addr) {
  const s = typeof addr === 'string' ? addr.trim() : ''
  if (!s) return 'unknown'
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s)
  return (mapped ? mapped[1] : s).slice(0, 128)
}

/** 会话绑定的客户端指纹键：UA 的短哈希；无 UA 头时为固定值（保持一致性即可）。 */
export function uaBindKey(userAgent) {
  return createHash('sha256').update(String(userAgent ?? '')).digest('hex').slice(0, 16)
}

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

/** scrypt 参数（哈希与校验共用，保证旧哈希仍可校验）。 */
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 }

/** 密码哈希格式：scrypt$N$r$p$saltB64$hashB64 */
function formatHash(N, r, p, salt, hash) {
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`
}

/** 解析自描述哈希；格式非法/参数超出安全范围返回 null（不抛）。 */
function parseHash(stored) {
  const parts = String(stored).split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null
  const N = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return null
  // 上界防御：被篡改的哈希文件不得让单次校验吃掉几百 MB 内存（DoS）
  if (N < 2 || N > 1 << 20 || r < 1 || r > 32 || p < 1 || p > 16) return null
  const salt = Buffer.from(parts[4], 'base64')
  const expected = Buffer.from(parts[5], 'base64')
  if (salt.length === 0 || expected.length === 0 || expected.length > 128) return null
  return { N, r, p, salt, expected }
}

/**
 * 密码校验（异步）：scrypt 交给 libuv 线程池，不阻塞事件循环。
 * 门卫与 dsh 同进程，同步 scrypt 每 ~40ms 会卡住整个服务（含正在流式输出的对话），
 * 全局节流只限制了频率（默认 30/分钟 ≈ 1.2s/分钟的累计阻塞）。
 * 返回布尔；哈希格式非法一律 false，绝不抛。
 */
export function verifyPasswordAsync(password, stored) {
  const parsed = parseHash(stored)
  if (!parsed) return Promise.resolve(false)
  return new Promise((resolve) => {
    try {
      scrypt(String(password), parsed.salt, parsed.expected.length, { N: parsed.N, r: parsed.r, p: parsed.p }, (err, actual) => {
        if (err || !actual) return resolve(false)
        try {
          resolve(actual.length === parsed.expected.length && timingSafeEqual(actual, parsed.expected))
        } catch {
          resolve(false)
        }
      })
    } catch {
      resolve(false)
    }
  })
}

/**
 * 全局认证计算节流：滑动窗口内限制「触发 scrypt 计算的请求数」。
 * 目的：即使攻击者轮换 IP+用户名绕开双维度锁定，也无法把门卫 CPU 打满
 * （每次 scrypt 约 20~100ms，超限直接 429，不消耗哈希计算）。
 */
export class GlobalAuthThrottle {
  constructor(maxPerWindow = 30, windowMs = 60_000) {
    this.maxPerWindow = Math.max(1, Number(maxPerWindow) || 30)
    this.windowMs = Math.max(1000, Number(windowMs) || 60_000)
    this.count = 0
    this.windowStart = 0
  }

  /**
   * 尝试占一个配额。返回 true=放行（计入窗口）；false=超限（不计入，不消耗计算）。
   */
  acquire(now = Date.now()) {
    if (now - this.windowStart >= this.windowMs) {
      this.windowStart = now
      this.count = 0
    }
    if (this.count >= this.maxPerWindow) return false
    this.count += 1
    return true
  }
}

// 预计算的哑哈希：用户名不存在时也执行一次等价 scrypt 计算，
// 抹平「账号存在与否」的响应时序差，防止用户名枚举。
const DUMMY_HASH = hashPassword('dsh-login-gateway-dummy-verify')

/** 假校验（异步）：仅消耗等价计算时间，结果无意义。 */
export function fakeVerifyAsync(password) {
  return verifyPasswordAsync(password, DUMMY_HASH).then(() => undefined)
}

/**
 * 弱口令黑名单：setup 与改密的新密码一律拒绝这些最常被爆破字典收录的模式。
 * 只拦「明显可猜」的，不做复杂度强制（避免可用性损失），配合限速已足够。
 */
const WEAK_PASSWORDS = new Set([
  '12345678', '123456789', '1234567890', '12345678a', '12341234', '11223344',
  '87654321', '0123456789', '123456780', '147258369', '159357888',
  'password', 'password1', 'password123',
  'passw0rd', 'p@ssw0rd', 'p@ssword',
  'qwerty123', 'qwertyuiop', 'qweasdzxc', '1qaz2wsx', '1q2w3e4r',
  'abcd1234', 'abc12345', 'a1234567', 'aa123456', 'asd12345',
  'iloveyou', 'sunshine', 'princess', 'football', 'baseball',
  'letmein123', 'welcome1', 'monkey123', 'admin123', 'root1234',
])

/**
 * 新密码强度检查：返回 null=通过；字符串=拒绝原因。
 * 规则：≥8 位（调用方已查）、非黑名单、非纯数字、非单一字符重复。
 */
export function checkNewPassword(password) {
  const p = String(password ?? '')
  if (WEAK_PASSWORDS.has(p.toLowerCase())) return '密码过于常见，容易被字典爆破，请更换'
  if (/^\d{8,}$/.test(p)) return '密码不能是纯数字'
  if (/^(.)\1{7,}$/u.test(p)) return '密码不能由同一字符重复组成'
  return null
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
 * 会话存储：内存 Map，token -> { username, expiresAt, bindKey }。
 * - maxSessions 上限防止已认证方反复登录把内存刷爆（逐出最旧会话）。
 * - bindKey：客户端绑定键（默认 User-Agent 哈希）。纯 HTTP 直连场景下 Cookie
 *   若被嗅探，攻击者换个客户端 UA 也无法复用；浏览器升级导致的 UA 变化
 *   只需重新登录一次。
 */
export class SessionStore {
  constructor(ttlMs, maxSessions = 1000) {
    this.ttlMs = ttlMs
    this.maxSessions = Math.max(1, Number(maxSessions) || 1000)
    this.sessions = new Map()
  }

  create(username, bindKey = null) {
    if (this.sessions.size >= this.maxSessions) {
      // Map 保持插入序：TTL 相同 ⇒ 最先插入即最先过期，逐出最旧
      const oldest = this.sessions.keys().next().value
      if (oldest !== undefined) this.sessions.delete(oldest)
    }
    const token = randomBytes(32).toString('hex')
    this.sessions.set(token, { username, expiresAt: Date.now() + this.ttlMs, bindKey })
    return token
  }

  /** 返回会话对象；不存在/过期/绑定键不符（返回 null 并吊销该 token）均不可用。 */
  get(token, bindKey) {
    if (!token) return null
    const s = this.sessions.get(token)
    if (!s) return null
    if (s.expiresAt < Date.now()) {
      this.sessions.delete(token)
      return null
    }
    if (bindKey !== undefined && s.bindKey !== null && s.bindKey !== undefined && s.bindKey !== bindKey) {
      // 绑定键不匹配：判定为令牌被异端复用，立即吊销
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
