/**
 * dsh-login-gateway 首次启动引导页（DeepSeek 品牌蓝方案，与登录页同风格，单文件内联 CSS/JS）。
 * 字段：一次性令牌、用户名、密码、确认密码；fetch POST /setup，
 * 成功跳转 /（登录页），失败在页内显示服务端错误。
 */
export const setupPageHtml = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>初始化设置 - dsh</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background:
    radial-gradient(900px 500px at 20% -10%, rgba(77, 107, 254, 0.22) 0%, transparent 60%),
    radial-gradient(700px 400px at 90% 110%, rgba(77, 107, 254, 0.12) 0%, transparent 55%),
    #010102;
  color: #f7f8f8;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
}
.card {
  width: min(92vw, 400px); background: rgba(15, 16, 17, 0.94);
  border: 1px solid rgba(77, 107, 254, 0.25); border-radius: 16px; padding: 44px 38px 38px;
  backdrop-filter: blur(12px); box-shadow: 0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.02) inset;
}
.brand { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.logo {
  width: 34px; height: 34px; border-radius: 9px; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #4D6BFE 0%, #6a5fc1 100%); font-weight: 700; font-size: 15px; color: #fff;
  box-shadow: 0 4px 16px rgba(77, 107, 254, 0.4);
}
.brand-name { font-size: 17px; font-weight: 600; letter-spacing: -0.3px; }
.brand-name em { font-style: normal; color: #4D6BFE; }
.sub { margin: 0 0 30px; font-size: 13px; color: #8a8f98; line-height: 1.6; }
label { display: block; font-size: 13px; color: #d0d6e0; margin-bottom: 16px; }
input {
  width: 100%; margin-top: 7px; padding: 11px 13px; font-size: 14px; color: #f7f8f8;
  background: #141516; border: 1px solid #2a2c33; border-radius: 10px; outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}
input::placeholder { color: #565b66; }
input:focus { border-color: #4D6BFE; box-shadow: 0 0 0 3px rgba(77, 107, 254, 0.18); }
button {
  width: 100%; margin-top: 8px; padding: 13px; font-size: 16px; font-weight: 400; letter-spacing: 6px; text-indent: 6px;
  color: #fff; background: linear-gradient(135deg, #3d5af0 0%, #2f49c8 100%); border: none; border-radius: 10px;
  cursor: pointer; transition: transform 0.15s, box-shadow 0.2s;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4);
}
button:hover { transform: translateY(-1px); box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5); }
button:active { transform: translateY(0); }
button:disabled { opacity: 0.5; cursor: default; transform: none; }
.foot { margin-top: 22px; text-align: center; font-size: 12px; color: #565b66; }
.error { min-height: 18px; margin: 12px 0 0; font-size: 13px; color: #ff6363; }
</style>
</head>
<body>
<main class="card">
  <div class="brand">
    <div class="logo">d</div>
    <div class="brand-name">deepseek <em>harness</em></div>
  </div>
  <p class="sub">首次使用请先创建管理员账号。一次性令牌显示在启动日志中，请先登录服务器查看。</p>
  <form id="setup-form" autocomplete="off">
    <label>一次性令牌
      <input id="token" name="token" placeholder="请输入一次性令牌" autocomplete="off" required>
    </label>
    <label>用户名
      <input id="username" name="username" placeholder="请输入用户名" autocomplete="off" maxlength="64" required>
    </label>
    <label>密码（至少 8 位）
      <input id="password" name="password" type="password" placeholder="请输入密码" autocomplete="new-password" required>
    </label>
    <label>确认密码
      <input id="password2" name="password2" type="password" placeholder="请再次输入密码" autocomplete="new-password" required>
    </label>
    <button type="submit">完成设置</button>
  </form>
  <p class="foot">DeepSeek Harness · 一切皆插件</p>
</main>
<script>
const form = document.getElementById('setup-form')
const btn = form.querySelector('button')

// error 占位不写死在 HTML：出错时才动态创建 p#error.error[role=alert] 插入表单后
function showError(msg) {
  let el = document.getElementById('error')
  if (!el) {
    el = document.createElement('p')
    el.id = 'error'
    el.className = 'error'
    el.setAttribute('role', 'alert')
    form.after(el)
  }
  el.textContent = msg
}
function clearError() {
  const el = document.getElementById('error')
  if (el) el.textContent = ''
}
form.addEventListener('submit', async (e) => {
  e.preventDefault()
  clearError()
  btn.disabled = true
  try {
    const res = await fetch('/setup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: document.getElementById('token').value.trim(),
        username: document.getElementById('username').value.trim(),
        password: document.getElementById('password').value,
        password2: document.getElementById('password2').value,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (res.ok && data.ok) window.location.href = '/'
    else showError(data.error || '设置失败，请重试')
  } catch {
    showError('网络错误，请重试')
  } finally {
    btn.disabled = false
  }
})
</script>
</body>
</html>`
