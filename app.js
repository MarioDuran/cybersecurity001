// app.js
const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8003;
const SALT_ROUNDS = 1
const ACC_DIR = path.join(__dirname, 'accounts');
fs.mkdirSync(ACC_DIR, { recursive: true });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  '/files',
  express.static(ACC_DIR, {
    dotfiles: 'deny',
    extensions: ['txt'],
    index: false,
    setHeaders(res) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
    },
  })
);

function esc(s = '') {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function safeName(u = '') {
  const s = String(u).trim().replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60);
  return s || ('user_' + Date.now());
}

// Página de registro
app.get('/', (req, res) => {
  res.send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>AUTH — REGISTRO</title>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <style>
      :root { --bg: #000; --panel: rgba(0,0,0,0.6); --glow: #00ff7f; --muted:#888; }
      html,body{height:100%;margin:0;background:var(--bg);font-family:"Courier New",monospace;color:var(--glow)}
      .wrap{height:100%;display:flex;align-items:center;justify-content:center;flex-direction:column;
            background-image: radial-gradient(circle at 10% 10%, rgba(0,255,127,0.035), transparent 10%),
                              linear-gradient(180deg, rgba(0,0,0,0.02), transparent 40%);}
      .console{width:520px;max-width:94%;padding:32px;background:var(--panel);border:1px solid rgba(0,255,127,0.08);
               box-shadow:0 0 40px rgba(0,255,127,0.04),inset 0 0 1px rgba(255,255,255,0.02);border-radius:10px;}
      h1{margin:0 0 12px 0;font-size:22px;letter-spacing:1px}
      label{display:block;margin-bottom:8px;font-size:13px;color:var(--muted)}
      .input{width:100%;padding:12px 14px;margin-top:6px;background:transparent;border:1px solid rgba(0,255,127,0.12);
             color:var(--glow);border-radius:6px;outline:none;box-sizing:border-box;font-size:14px}
      .row{margin-bottom:14px}
      .btn{width:100%;padding:12px;border-radius:6px;border:1px solid rgba(0,255,127,0.18);
           background:linear-gradient(90deg, rgba(0,255,127,0.12), rgba(0,255,127,0.06));
           color:var(--glow);font-weight:700;letter-spacing:1px;cursor:pointer;font-size:14px}
      .btn:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(0,255,127,0.03)}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="console" role="main" aria-labelledby="title">
        <h1 id="title">AUTH — REGISTRO</h1>
        <form method="POST" action="/create" autocomplete="off" novalidate>
          <div class="row">
            <label>usuario</label>
            <input class="input" name="username" placeholder="usuario" />
          </div>
          <div class="row">
            <label>password</label>
            <input class="input" name="password" type="password" placeholder="password" />
          </div>
          <button class="btn" type="submit">REGISTRAR</button>
        </form>
      </div>
    </div>
  </body>
</html>`);
});

// Creación y acceso al .txt propio
app.post('/create', async (req, res) => {
  try {
    const rawUser = String(req.body.username || '');
    const displayUser = rawUser; // mostrado en ACCESS
    const fileUser = safeName(rawUser); // nombre de archivo seguro
    const pwd = String(req.body.password || '');
    const filePath = path.join(ACC_DIR, fileUser + '.txt');

    if (!fs.existsSync(filePath)) {
      const hash = await bcrypt.hash(pwd, SALT_ROUNDS);
      fs.writeFileSync(filePath, hash + '\n', { flag: 'wx', mode: 0o600 });
    }

    res.send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>ACCESS — ${esc(displayUser)}</title>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <style>
      :root{--bg:#000;--glow:#00ff7f;--muted:#888}
      html,body{height:100%;margin:0;background:var(--bg);font-family:"Courier New",monospace;color:var(--glow)}
      .wrap{height:100%;display:flex;align-items:center;justify-content:center;flex-direction:column}
      .panel{padding:40px;background:rgba(0,0,0,0.6);border-radius:10px;border:1px solid rgba(0,255,127,0.08);text-align:center;min-width:320px}
      h1{font-size:28px;margin:0 0 8px 0;letter-spacing:2px}
      .btn{padding:10px 14px;border-radius:6px;border:1px solid rgba(0,255,127,0.18);background:transparent;color:var(--glow);cursor:pointer}
      a{color:var(--glow);text-decoration:none;border-bottom:1px dashed rgba(0,255,127,0.35)}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="panel" role="main" aria-labelledby="grant">
        <h1 id="grant">ACCESS — ${esc(displayUser)}</h1>
        <p><a href="/files/${encodeURIComponent(fileUser)}.txt" download>descargar .txt</a></p>
        <form method="POST" action="/logout" style="margin-top:18px">
          <button class="btn" type="submit">cerrar sesión</button>
        </form>
      </div>
    </div>
  </body>
</html>`);
  } catch {
    res.redirect('/');
  }
});

// Página con acceso a todos los .txt y hashes
app.get('/vault', (req, res) => {
  let items = [];
  try {
    items = fs
      .readdirSync(ACC_DIR, { withFileTypes: true })
      .filter((d) => d.isFile() && d.name.endsWith('.txt'))
      .map((d) => d.name);
  } catch {}

  const rows = items
    .map((name) => {
      const fp = path.join(ACC_DIR, name);
      let content = '';
      try { content = fs.readFileSync(fp, 'utf8').trim(); } catch {}
      const user = name.replace(/\.txt$/i, '');
      return `<li><code>${esc(user)}</code> — <code>${esc(content)}</code> — <a href="/files/${encodeURIComponent(user)}.txt" download>descargar .txt</a></li>`;
    })
    .join('');

  res.send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>VAULT</title>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <style>
      :root{--bg:#000;--glow:#00ff7f;--muted:#888}
      html,body{height:100%;margin:0;background:var(--bg);font-family:"Courier New",monospace;color:var(--glow)}
      .wrap{min-height:100%;display:flex;align-items:center;justify-content:center;flex-direction:column}
      .panel{width:860px;max-width:94%;padding:32px;background:rgba(0,0,0,0.6);border-radius:10px;border:1px solid rgba(0,255,127,0.08)}
      ul{list-style:none;padding:0;margin:0}
      li{padding:8px 0;border-bottom:1px dashed rgba(0,255,127,0.08)}
      a{color:var(--glow);text-decoration:none;border-bottom:1px dashed rgba(0,255,127,0.35)}
      code{background:rgba(0,0,0,0.25);padding:2px 6px;border-radius:6px}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="panel" role="main">
        <ul>${rows || '<li style="color:#888"> </li>'}</ul>
      </div>
    </div>
  </body>
</html>`);
});

app.post('/logout', (req, res) => {
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log('Server listening on http://localhost:' + PORT);
});
