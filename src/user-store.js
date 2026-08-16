/**
 * dsh-login-gateway 用户存储：JSON 文件 + 原子写入（同步版本）。
 * 仅在插件启动阶段一次性调用；零外部依赖，只使用 node:fs 与 node:path。
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/**
 * 读取用户文件，返回用户数组 `[{ username, passwordHash, createdAt }]`。
 * 文件不存在返回 null；文件存在但格式损坏则抛出带中文信息的错误。
 */
export function loadUsersSync(path) {
  let raw
  try {
    raw = readFileSync(path, 'utf8')
  } catch (err) {
    if (err?.code === 'ENOENT') return null
    throw err
  }
  let data
  try {
    data = JSON.parse(raw)
  } catch {
    throw new Error(`用户文件格式错误（不是有效 JSON）：${path}`)
  }
  if (!data || !Array.isArray(data.users)) {
    throw new Error(`用户文件格式错误（缺少 users 数组）：${path}`)
  }
  return data.users
}

/**
 * 原子写入用户文件：先写临时文件再 rename，避免写一半损坏。
 * 自动创建父目录（默认 ~/.dsh-login-gateway 可能不存在）。
 */
export function saveUsersSync(path, users) {
  mkdirSync(dirname(path), { recursive: true })
  const tmp = `${path}.${process.pid}.tmp`
  writeFileSync(tmp, `${JSON.stringify({ users }, null, 2)}\n`, 'utf8')
  renameSync(tmp, path)
}
