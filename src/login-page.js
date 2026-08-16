/**
 * dsh-login-gateway 登录页（DeepSeek 品牌蓝方案，中文、深色主题、单文件内联 CSS/JS，零外部资源）。
 * 表单 AJAX POST /login：成功跳转 /（已登录后走反代），失败在页内显示服务端错误。
 */
export const loginPageHtml = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 - dsh</title>
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
  <p class="sub">登录以访问您的智能体工作台</p>
  <form id="login-form">
    <label>用户名
      <input id="username" name="username" type="text" placeholder="请输入用户名" autocomplete="username" required>
    </label>
    <label>密码
      <input id="password" name="password" type="password" placeholder="请输入密码" autocomplete="current-password" required>
    </label>
    <button type="submit">登 录</button>
  </form>
  <p id="error" class="error" role="alert"></p>
  <p class="foot">DeepSeek Harness · 一切皆插件</p>
</main>
<script>
const form = document.getElementById('login-form')
const error = document.getElementById('error')
const btn = form.querySelector('button')
form.addEventListener('submit', async (e) => {
  e.preventDefault()
  error.textContent = ''
  btn.disabled = true
  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (res.ok && data.ok) window.location.href = '/'
    else error.textContent = data.error || '登录失败，请稍后重试'
  } catch {
    error.textContent = '网络错误，请稍后重试'
  } finally {
    btn.disabled = false
  }
})
</script>
</body>
</html>`
