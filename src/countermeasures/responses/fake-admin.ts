/** Fake admin login page response */
export function fakeAdminPageResponse(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Panel - Login</title>
<style>
body { font-family: Arial, sans-serif; background: #1a1a2e; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
.box { background: #fff; padding: 40px; border-radius: 8px; width: 360px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
h2 { text-align:center; color:#333; margin-bottom:24px; }
input { width:100%; padding:10px; margin:8px 0; box-sizing:border-box; border:1px solid #ddd; border-radius:4px; }
button { width:100%; padding:12px; background:#e74c3c; color:white; border:none; border-radius:4px; cursor:pointer; font-size:16px; }
button:hover { background:#c0392b; }
.version { text-align:center; font-size:11px; color:#999; margin-top:20px; }
</style>
</head>
<body>
<div class="box">
  <h2>🔐 Admin Panel</h2>
  <form method="POST" action="/admin/login">
    <input type="text" name="username" placeholder="Username" autocomplete="off">
    <input type="password" name="password" placeholder="Password" autocomplete="off">
    <input type="hidden" name="_csrf" value="a8f3d2c1e4b7f6a3">
    <button type="submit">Sign In</button>
  </form>
  <div class="version">v2.4.1 — Internal Use Only</div>
</div>
</body>
</html>`
}
