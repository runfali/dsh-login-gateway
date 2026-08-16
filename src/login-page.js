/**
 * dsh-login-gateway 中文登录页：深色主题、内联 CSS/JS、无外部资源。
 */

export const loginPageHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepSeek Harness 登录</title>
<style>
:root {
  --bg: #0b0d14;
  --panel: #141826;
  --text: #e7e9f0;
  --muted: #9aa2b8;
  --border: #262c40;
  --accent: #a78bfa;
  --accent2: #c8f26a;
  --error: #f87171;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: radial-gradient(1200px 600px at 50% -10%, #1b2136 0%, var(--bg) 60%);
  color: var(--text);
  font-family: "PingFang SC", "Microsoft YaHei", "Segoe UI", system-ui, sans-serif;
}
.card {
  width: 360px;
  max-width: calc(100vw - 32px);
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 36px 32px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, .45);
}
h1 { margin: 0 0 4px; font-size: 22px; letter-spacing: .5px; }
h1::before { content: "◆"; color: var(--accent2); margin-right: 8px; font-size: 14px; }
.sub { margin: 0 0 28px; color: var(--muted); font-size: 13px; }
label { display: block; font-size: 13px; color: var(--muted); margin: 16px 0 6px; }
input {
  width: 100%;
  padding: 10px 12px;
  background: #0d1018;
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  font-size: 14px;
  outline: none;
}
input:focus { border-color: var(--accent); }
button {
  width: 100%;
  margin-top: 24px;
  padding: 11px;
  border: none;
  border-radius: 8px;
  background: linear-gradient(135deg, var(--accent), #7c5cff);
  color: #fff;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
}
button:hover { filter: brightness(1.08); }
button:disabled { opacity: .6; cursor: not-allowed; }
.error {
  margin-top: 16px;
  padding: 9px 12px;
  border: 1px solid rgba(248, 113, 113, .4);
  background: rgba(248, 113, 113, .12);
  color: var(--error);
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.5;
}
.foot { margin: 26px 0 0; color: var(--muted); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<main class="card">
  <h1>DeepSeek Harness</h1>
  <p class="sub">请登录以访问 Web 控制台</p>
  <form id="login">
    <label for="username">用户名</label>
    <input id="username" name="username" autocomplete="username" required>
    <label for="password">密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <div id="error" class="error" hidden></div>
    <button type="submit">登 录</button>
  </form>
  <p class="foot">仅限授权人员访问 · 连续失败将触发临时锁定</p>
</main>
<script>
var form = document.getElementById('login')
var errorBox = document.getElementById('error')
var btn = form.querySelector('button')

function showError(msg) {
  errorBox.textContent = msg
  errorBox.hidden = false
}

form.addEventListener('submit', async function (e) {
  e.preventDefault()
  errorBox.hidden = true
  btn.disabled = true
  try {
    var res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
      })
    })
    var data = await res.json().catch(function () { return {} })
    if (res.ok && data.ok) {
      location.reload()
      return
    }
    var msg = data.error || '登录失败，请重试'
    if (typeof data.remaining === 'number') {
      msg += '，还可尝试 ' + data.remaining + ' 次'
    }
    showError(msg)
  } catch (err) {
    showError('网络错误，请稍后重试')
  } finally {
    btn.disabled = false
  }
})
</script>
</body>
</html>
`
