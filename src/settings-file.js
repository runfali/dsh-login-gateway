/**
 * 门卫托管的 dsh 设置文件下载支持。
 *
 * 背景：dsh 设置页的"打开配置文件"会调用宿主机系统级打开（Linux 走 xdg-open）。
 * 无桌面/无显示器的主机（常见于容器/服务器）上该操作必然失败，前端只显示
 * "无法打开配置文件"。门卫探测到宿主无法原生打开时，注入脚本把该按钮改指到
 * 门卫自己的下载路由（见 proxy.js 的 SETTINGS_DOWNLOAD_TAG），此处提供实际的
 * 文件读取逻辑，让远端用户也能直接取回 ~/.dsh/settings.yaml。
 */

import { readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** dsh 设置文件默认位置（与 dsh 的 dshHome 默认一致：<home>/.dsh/settings.yaml）。 */
export function defaultSettingsFilePath() {
  return path.join(os.homedir(), '.dsh', 'settings.yaml')
}

/**
 * 读取配置并构造下载响应。
 * 文件较小（KB 级），一次性读取；在文件头部追加两行注释注明路径与来源，
 * 仍为合法 YAML。
 * @param {string} filePath 设置文件绝对路径
 * @returns {{ ok: boolean, status: number, headers: Record<string,string>, body?: Buffer, reason?: string }}
 */
export function settingsFilePayload(filePath) {
  let raw
  try {
    raw = readFileSync(filePath)
  } catch (err) {
    if (err.code === 'ENOENT') return { ok: false, status: 404, reason: `配置文件不存在：${filePath}` }
    return { ok: false, status: 500, reason: `读取配置文件失败：${err?.message ?? err}` }
  }
  const header = Buffer.from(`# dsh settings file: ${filePath}\n# via dsh-login-gateway (browser download)\n\n`, 'utf8')
  return {
    ok: true,
    status: 200,
    headers: {
      'content-type': 'text/yaml; charset=utf-8',
      'content-disposition': 'attachment; filename="settings.yaml"',
      'content-length': String(header.length + raw.length),
      'x-content-type-options': 'nosniff',
    },
    body: Buffer.concat([header, raw]),
  }
}
