/**
 * 供应链约束的守护测试（可执行的不变量，不是文档口号）。
 *
 * 约束来源（发哥 2026-09-10 提出，与 dsh 社区对插件作者的建议一致）：
 *   1. 插件不得依赖任何 npm 安装脚本（preinstall/install/postinstall/prepare…）
 *   2. 不得引入 node-gyp / 原生扩展（binding.gyp / *.node）
 *   3. 能预编译的产物一律随包提交，安装期零构建
 *
 * 本仓当前天然满足（零依赖 + 纯 ESM + 手写预编译 client bundle），这组用例把
 * 「天然满足」变成「不可回退」：任何未来改动引入脚本/原生/构建期依赖都会在此炸出。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'))

/** npm 会在安装/发布各时机自动执行的生命周期钩子——全部禁止。 */
const FORBIDDEN_LIFECYCLE = [
  'preinstall', 'install', 'postinstall',
  'prepublish', 'prepublishOnly', 'prepare',
  'prepack', 'postpack',
]

/** 递归列出仓库内（跳过 node_modules/.git）的所有文件。 */
function listFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git' || name === 'graphify-out' || name === '.code-review-graph') continue
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) listFiles(full, out)
    else out.push(full)
  }
  return out
}

test('禁止安装脚本：package.json 不得声明任何 npm 生命周期钩子', () => {
  const scripts = pkg.scripts ?? {}
  const hits = FORBIDDEN_LIFECYCLE.filter((hook) => hook in scripts)
  assert.deepEqual(hits, [], `出现被禁的生命周期脚本：${hits.join(', ')}`)
  // 只允许与安装无关的开发期脚本
  const allowed = new Set(['test'])
  const unexpected = Object.keys(scripts).filter((k) => !allowed.has(k))
  assert.deepEqual(unexpected, [], `未在允许清单内的 scripts：${unexpected.join(', ')}（新增前请确认它不在安装期执行）`)
})

test('零运行时依赖：dependencies / optionalDependencies / peerDependencies 必须为空', () => {
  assert.equal(pkg.dependencies ?? undefined, undefined, '不得有 dependencies')
  assert.equal(pkg.optionalDependencies ?? undefined, undefined, '不得有 optionalDependencies')
  assert.equal(pkg.peerDependencies ?? undefined, undefined, '不得有 peerDependencies（宿主服务用 ctx.inject 声明）')
  assert.equal(pkg.bundleDependencies ?? undefined, undefined)
})

test('禁止 gyp / 原生扩展：无 binding.gyp、无 .node 产物、无 node-gyp 依赖', () => {
  assert.equal(pkg.gypfile ?? undefined, undefined, '不得声明 gypfile')
  const files = listFiles(root)
  const offenders = files.filter((f) => /(^|\/)binding\.gyp$|\.node$|\.gyp$|\.dll$|\.so$/.test(f))
  assert.deepEqual(offenders.map((f) => path.relative(root, f)), [], '存在原生扩展或 gyp 配置')
  // 源码里不得出现原生加载 / 构建期调用
  const srcFiles = files.filter((f) => /\.(js|mjs|cjs|json|ya?ml)$/.test(f) && !f.includes('/test/'))
  const bad = []
  for (const f of srcFiles) {
    const text = readFileSync(f, 'utf8')
    if (/node-gyp|nodeGyp|\bdlopen\b|process\.dlopen|gypfile/.test(text)) bad.push(path.relative(root, f))
  }
  assert.deepEqual(bad, [], '源码中出现原生构建痕迹')
})

test('安装期零构建：不引用任何第三方包，全部 import 来自 node: 内置或相对路径', () => {
  const srcDirs = ['src', 'lib', 'bin']
  const offenders = []
  for (const dir of srcDirs) {
    for (const f of listFiles(path.join(root, dir))) {
      if (!/\.(js|mjs)$/.test(f)) continue
      const text = readFileSync(f, 'utf8')
      // 匹配 import ... from 'x' / import('x') / require('x')
      const specs = [
        ...text.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g),
        ...text.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
        ...text.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
      ].map((m) => m[1])
      for (const s of specs) {
        if (s.startsWith('node:') || s.startsWith('./') || s.startsWith('../')) continue
        offenders.push(`${path.relative(root, f)} → ${s}`)
      }
    }
  }
  assert.deepEqual(offenders, [], '出现外部模块引用（会带来依赖树与安装脚本案）')
})

test('client bundle 是随包提交的预编译产物：零 require，且注册 id 等于包名', () => {
  const bundle = readFileSync(path.join(root, 'lib/client.js'), 'utf8')
  assert.equal(bundle.includes('require('), false, 'client bundle 不得 require 外部模块')
  assert.match(bundle, new RegExp(`id: "${pkg.name}"`), '工厂 id 必须等于包名')
  // 产物内联进包，安装期不需要任何构建步骤
  assert.equal(typeof pkg.scripts?.build, 'undefined', '不得存在 build 脚本（产物随包提交）')
})

test('发布面（files 字段）只含运行所需与说明文件，不含内部文档', () => {
  const files = pkg.files ?? []
  for (const required of ['bin', 'src', 'lib', 'cordis.patch.yml', 'README.md', 'LICENSE']) {
    assert.ok(files.includes(required), `files 必须包含 ${required}`)
  }
  assert.ok(!files.includes('docs'), '内部文档（docs/）不得随包发布')
  assert.ok(!files.includes('test'), '测试不随包发布')
})

test('.gitignore 忽略内部文档目录', () => {
  const ignore = readFileSync(path.join(root, '.gitignore'), 'utf8')
  assert.match(ignore, /^docs\/$/m, 'docs/ 必须被 git 忽略（内部审计与调研文档不外发）')
})

test('版本与兼容声明一致：engines 区间必须覆盖本仓库当前版本', () => {
  // npm semver 预发布规则：区间内必须出现同元组预发布，预发布版才被满足。
  // 这条用例用「手工判定表」把该规则固化，防止再出现「声明 0.1.5 却不被自己区间覆盖」。
  const range = pkg.dsh?.engines?.dsh
  assert.ok(typeof range === 'string' && range.length > 0, '必须声明 dsh.engines.dsh')
  const version = pkg.version
  const parse = (v) => {
    const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(v)
    if (!m) throw new Error(`无法解析版本：${v}`)
    return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ?? null }
  }
  const cmp = (a, b) => {
    for (const k of ['major', 'minor', 'patch']) if (a[k] !== b[k]) return a[k] < b[k] ? -1 : 1
    if (a.pre === b.pre) return 0
    if (a.pre === null) return 1 // 正式版 > 预发布
    if (b.pre === null) return -1
    const an = a.pre.split('.'), bn = b.pre.split('.')
    for (let i = 0; i < Math.max(an.length, bn.length); i++) {
      const x = an[i], y = bn[i]
      if (x === undefined) return -1
      if (y === undefined) return 1
      const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y)
      if (nx && ny) { if (+x !== +y) return +x < +y ? -1 : 1; continue }
      if (nx !== ny) return nx ? -1 : 1
      if (x !== y) return x < y ? -1 : 1
    }
    return 0
  }
  // 逐段判定：'||' 分割，每段由 >= 下界与 < 上界组成
  const satisfied = range.split('||').some((clause) => {
    const [lo, hi] = clause.trim().split(/\s+/)
    if (!lo?.startsWith('>=') || !hi?.startsWith('<')) return false
    const lower = parse(lo.slice(2)), upper = parse(hi.slice(1)), ver = parse(version)
    if (cmp(ver, lower) < 0) return false
    if (cmp(ver, upper) >= 0) return false
    // 预发布例外：版本本身是预发布时，需同元组预发布出现在区间内
    if (ver.pre !== null) {
      const sameTuplePreInRange = lower.pre !== null && lower.major === ver.major && lower.minor === ver.minor && lower.patch === ver.patch
        || upper.pre !== null && upper.major === ver.major && upper.minor === ver.minor && upper.patch === ver.patch
      if (!sameTuplePreInRange) return false
    }
    return true
  })
  assert.ok(satisfied, `本仓库版本 ${version} 不被自己声明的 engines 区间「${range}」覆盖`)
})

test('engines 必须显式覆盖 0.1.5 预发布段（本仓的目标 dsh 版本）', () => {
  const range = pkg.dsh?.engines?.dsh ?? ''
  // 只要区间里出现 >=0.1.5-alpha.x 或 >=0.1.5-rc.x，即认为覆盖（配合上一条的通用判定）
  assert.match(range, />=\s*0\.1\.5-(alpha|beta|rc)\.\d+/, 'engines 需显式包含 0.1.5 预发布下界')
})
