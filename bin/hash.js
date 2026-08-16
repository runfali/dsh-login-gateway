#!/usr/bin/env node
/**
 * dsh-login-gateway 密码哈希生成工具。
 * 用法：dsh-login-gateway-hash <密码>
 * 输出 scrypt 自描述哈希，用于 users 配置或用户文件中的 passwordHash 字段。
 */

import { hashPassword } from '../src/auth.js'

const password = process.argv[2]
if (!password) {
  console.error('用法：dsh-login-gateway-hash <密码>')
  console.error('')
  console.error('生成 scrypt 密码哈希（自描述格式），用于 users 配置或用户文件中的 passwordHash 字段。')
  console.error('示例：dsh-login-gateway-hash "我的密码"')
  process.exit(1)
}
console.log(hashPassword(password))
