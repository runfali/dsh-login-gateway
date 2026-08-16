/**
 * dsh-login-gateway 首次启动引导页（中文、深色主题，与登录页一致风格）。
 * 字段：一次性令牌、用户名、密码、确认密码；fetch POST /setup，
 * 成功跳转 /（登录页），失败在页内显示服务端错误。
 */
export const setupPageHtml = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>初始化设置 - dsh 登录门卫</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #010102; color: #f7f8f8;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
}
.card {
  width: min(92vw, 420px); background: #0f1011; border: 1px solid #23252a;
  border-radius: 12px; padding: 36px 32px;
}
h1 { margin: 0 0 6px; font-size: 22px; font-weight: 600; letter-spacing: -0.4px; }
.sub { margin: 0 0 24px; font-size: 14px; color: #8a8f98; line-height: 1.6; }
label { display: block; font-size: 13px; color: #d0d6e0; margin-bottom: 14px; }
input {
  width: 100%; margin-top: 6px; padding: 10px 12px; font-size: 14px; color: #f7f8f8;
  background: #141516; border: 1px solid #23252a; border-radius: 8px; outline: none;
}
input:focus { border-color: #5e6ad2; box-shadow: 0 0 0 3px rgba(94, 106, 210, 0.25); }
button {
  width: 100%; margin-top: 6px; padding: 10px; font-size: 14px; font-weight: 600;
  color: #fff; background: #5e6ad2; border: none; border-radius: 8px; cursor: pointer;
}
button:hover { background: #828fff; }
button:disabled { opacity: 0.5; cursor: default; }
.error { min-height: 18px; margin: 14px 0 0; font-size: 13px; color: #ff6363; }
</style>
</head>
<body>
<main class="card">
  <h1>初始化设置</h1>
  <p class="sub">首次使用请先创建管理员账号。一次性令牌显示在启动日志中，请先登录服务器查看。</p>
  <form id="setup-form" autocomplete="off">
    <label>一次性令牌
      <input id="token" name="token" autocomplete="off" required>
    </label>
    <label>用户名
      <input id="username" name="username" autocomplete="off" maxlength="64" required>
    </label>
    <label>密码（至少 8 位）
      <input id="password" name="password" type="password" autocomplete="new-password" required>
    </label>
    <label>确认密码
      <input id="password2" name="password2" type="password" autocomplete="new-password" required>
    </label>
    <button type="submit">完成设置</button>
  </form>
  <p id="error" class="error" role="alert"></p>
</main>
<script>
const form = document.getElementById('setup-form')
const error = document.getElementById('error')
const btn = form.querySelector('button')
form.addEventListener('submit', async (e) => {
  e.preventDefault()
  error.textContent = ''
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
    else error.textContent = data.error || '设置失败，请重试'
  } catch {
    error.textContent = '网络错误，请重试'
  } finally {
    btn.disabled = false
  }
})
</script>
</body>
</html>`
