#!/usr/bin/env node
/**
 * dsh-login-gateway 密码哈希 CLI。
 * 用法：dsh-login-gateway-hash <明文密码>
 * 输出 scrypt 哈希（scrypt$N$r$p$salt$hash），写入 cordis.patch.yml 的 users[].passwordHash。
 */

import { hashPassword } from '../src/auth.js'

const password = process.argv[2]

if (!password) {
  console.log('用法：dsh-login-gateway-hash <明文密码>')
  console.log('')
  console.log('生成 scrypt 密码哈希，用于配置插件 users 列表的 passwordHash 字段。')
  console.log('示例：')
  console.log('  dsh-login-gateway-hash my-secret-password')
  console.log('  dsh-login-gateway-hash my-secret-password > /tmp/hash.txt')
  process.exit(1)
}

console.log(hashPassword(password))
