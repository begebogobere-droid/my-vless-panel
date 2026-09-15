// پنل مدیریت + API + VLESS handler — نسخه Node.js برای اجرا روی Railway
// معادل Node.js همون worker.js قبلی (Cloudflare Worker)
// دیتابیس: SQLite محلی (better-sqlite3) به‌جای Cloudflare D1
// اتصال TCP خام: ماژول net به‌جای cloudflare:sockets

const fs = require("fs");
const path = require("path");
const net = require("net");
const crypto = require("crypto");
const express = require("express");
const { WebSocketServer } = require("ws");
const Database = require("better-sqlite3");

const PORT = process.env.PORT || 8080;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || process.env.ADMIN_PASSWORD || "changeme";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "app.db");

// ---------------- DB init ----------------

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
const schema = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
db.exec(schema);

// ---------------- App setup ----------------

const app = express();
app.use(express.json());

function checkAuth(req) {
  const auth = req.headers["authorization"] || "";
  return auth === `Bearer ${ADMIN_TOKEN}`;
}

// ---------------- Users API ----------------

app.get("/api/users", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  const results = db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
  res.json(results);
});

app.post("/api/users", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  const body = req.body || {};
  const uuid = crypto.randomUUID();
  const name = body.name || "";
  const trafficLimit = Number(body.traffic_limit_gb || 0) * 1024 * 1024 * 1024;
  const expiresAt = body.expires_at ? Math.floor(new Date(body.expires_at).getTime() / 1000) : null;

  db.prepare(
    `INSERT INTO users (uuid, name, traffic_limit_bytes, expires_at, enabled) VALUES (?, ?, ?, ?, 1)`
  ).run(uuid, name, trafficLimit, expiresAt);

  res.json({ uuid, name, traffic_limit_gb: body.traffic_limit_gb || 0, expires_at: body.expires_at || null });
});

app.patch("/api/users/:id", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  const id = req.params.id;
  const body = req.body || {};
  const fields = [];
  const values = [];

  if (body.name !== undefined) { fields.push("name = ?"); values.push(body.name); }
  if (body.traffic_limit_gb !== undefined) {
    fields.push("traffic_limit_bytes = ?");
    values.push(Number(body.traffic_limit_gb) * 1024 * 1024 * 1024);
  }
  if (body.expires_at !== undefined) {
    fields.push("expires_at = ?");
    values.push(body.expires_at ? Math.floor(new Date(body.expires_at).getTime() / 1000) : null);
  }
  if (body.enabled !== undefined) { fields.push("enabled = ?"); values.push(body.enabled ? 1 : 0); }
  if (body.reset_traffic) { fields.push("traffic_used_bytes = 0"); }

  if (fields.length === 0) return res.status(400).json({ error: "nothing to update" });

  values.push(id);
  db.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).run(...values);
  res.json({ ok: true });
});

app.delete("/api/users/:id", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

// ---------------- Clean IPs API ----------------

app.get("/api/ips", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  const results = db.prepare("SELECT * FROM clean_ips ORDER BY created_at DESC").all();
  res.json(results);
});

app.post("/api/ips", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  const body = req.body || {};
  const raw = (body.ips || "").toString();
  const list = raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  if (list.length === 0) return res.status(400).json({ error: "no ips provided" });

  const stmt = db.prepare("INSERT INTO clean_ips (ip, note, active) VALUES (?, ?, 1)");
  const insertMany = db.transaction((ips) => {
    for (const ip of ips) stmt.run(ip, body.note || null);
  });
  insertMany(list);

  res.json({ added: list.length });
});

app.patch("/api/ips/:id", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  const body = req.body || {};
  db.prepare("UPDATE clean_ips SET active = ? WHERE id = ?").run(body.active ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

app.delete("/api/ips/:id", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  db.prepare("DELETE FROM clean_ips WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

// ---------------- Subscription ----------------

app.get("/sub/:uuid", (req, res) => {
  const uuid = req.params.uuid;
  const user = db.prepare("SELECT * FROM users WHERE uuid = ?").get(uuid);
  if (!user || !user.enabled) return res.status(404).send("not found");
  if (user.expires_at && user.expires_at < Math.floor(Date.now() / 1000)) {
    return res.status(403).send("expired");
  }

  const ips = db.prepare("SELECT ip, note FROM clean_ips WHERE active = 1 ORDER BY created_at DESC").all();
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const name = encodeURIComponent(user.name || "user");

  let links;
  if (ips.length === 0) {
    links = [`vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2F#${name}`];
  } else {
    links = ips.map((row) => {
      const label = encodeURIComponent(`${user.name || "user"}-${row.note || row.ip}`);
      return `vless://${uuid}@${row.ip}:443?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2F#${label}`;
    });
  }

  const body = links.join("\n");
  const b64 = Buffer.from(body, "utf8").toString("base64");
  res.set("content-type", "text/plain; charset=utf-8").send(b64);
});

// ---------------- Panel ----------------

app.get("/panel", (req, res) => {
  res.set("content-type", "text/html; charset=utf-8").send(PANEL_HTML);
});

app.get("/", (req, res) => {
  res.status(200).send("OK");
});

// ---------------- VLESS over WebSocket ----------------

function bytesToUuid(bytes) {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function parseVlessHeader(buf) {
  if (buf.length < 24) return null;
  let offset = 0;
  const version = buf[offset]; offset += 1;
  const uuid = bytesToUuid(buf.slice(offset, offset + 16)); offset += 16;
  const addonsLen = buf[offset]; offset += 1;
  offset += addonsLen;
  const cmd = buf[offset]; offset += 1;
  if (cmd !== 1) return null;
  const port = (buf[offset] << 8) | buf[offset + 1]; offset += 2;
  const atyp = buf[offset]; offset += 1;
  let addr;
  if (atyp === 1) { addr = buf.slice(offset, offset + 4).join("."); offset += 4; }
  else if (atyp === 2) { const len = buf[offset]; offset += 1; addr = buf.slice(offset, offset + len).toString("utf8"); offset += len; }
  else if (atyp === 3) {
    const p = [];
    for (let i = 0; i < 8; i++) { p.push(((buf[offset] << 8) | buf[offset + 1]).toString(16)); offset += 2; }
    addr = p.join(":");
  } else return null;
  return { version, uuid, port, addr, payload: buf.slice(offset) };
}

const server = app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (request, socket, head) => {
  // فقط مسیرهای غیر پنل/API رو به عنوان اتصال VLESS در نظر بگیر
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit("connection", ws, request);
  });
});

wss.on("connection", (ws) => {
  let remoteSocket = null;
  let handshakeDone = false;
  let dbUser = null;
  let usedThisSession = 0;

  ws.on("message", async (data) => {
    try {
      const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);

      if (!handshakeDone) {
        const parsed = parseVlessHeader(chunk);
        if (!parsed) { ws.close(1008, "bad header"); return; }

        dbUser = db.prepare("SELECT * FROM users WHERE uuid = ?").get(parsed.uuid);
        if (!dbUser || !dbUser.enabled) { ws.close(1008, "unauthorized"); return; }
        if (dbUser.expires_at && dbUser.expires_at < Math.floor(Date.now() / 1000)) {
          ws.close(1008, "expired"); return;
        }
        if (dbUser.traffic_limit_bytes > 0 && dbUser.traffic_used_bytes >= dbUser.traffic_limit_bytes) {
          ws.close(1008, "quota exceeded"); return;
        }

        ws.send(Buffer.from([parsed.version, 0]));

        remoteSocket = net.connect({ host: parsed.addr, port: parsed.port });

        remoteSocket.on("data", (buf) => {
          usedThisSession += buf.length;
          if (ws.readyState === ws.OPEN) ws.send(buf);
        });
        remoteSocket.on("error", (err) => {
          console.error("remote socket error:", err.message);
          try { ws.close(1011, "remote error"); } catch (_) {}
        });
        remoteSocket.on("close", () => {
          try { ws.close(1000, "remote closed"); } catch (_) {}
        });

        if (parsed.payload.length > 0) {
          usedThisSession += parsed.payload.length;
          remoteSocket.write(parsed.payload);
        }

        handshakeDone = true;
        return;
      }

      if (remoteSocket) {
        usedThisSession += chunk.length;
        remoteSocket.write(chunk);
      }
    } catch (err) {
      console.error("message error:", err.message);
      try { ws.close(1011, "stream error"); } catch (_) {}
    }
  });

  ws.on("close", () => {
    if (remoteSocket) { try { remoteSocket.destroy(); } catch (_) {} }
    if (dbUser && usedThisSession > 0) {
      db.prepare("UPDATE users SET traffic_used_bytes = traffic_used_bytes + ? WHERE id = ?")
        .run(usedThisSession, dbUser.id);
    }
  });
});

// ---------------- Panel UI (همون HTML قبلی، بدون تغییر) ----------------

const PANEL_HTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل مدیریت کانفیگ</title>
<style>
:root {
  --bg:#0b0d12; --panel:#12151c; --border:#242833; --text:#e8eaed; --muted:#8b91a0;
  --blue:#3b82f6; --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
}
* { box-sizing:border-box; }
body { font-family: Vazirmatn, Tahoma, sans-serif; background:var(--bg); color:var(--text); padding:20px; margin:0; }
h1 { font-size:19px; margin:0 0 4px; }
.sub { color:var(--muted); font-size:12px; margin-bottom:20px; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; margin-bottom:16px; }
.card h3 { margin:0 0 12px; font-size:13px; color:var(--muted); font-weight:normal; }
.row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
input, button, select { padding:8px 12px; border-radius:8px; border:1px solid var(--border); background:#1a1e28; color:var(--text); font-size:13px; }
input { min-width:140px; flex:1; }
button { cursor:pointer; background:var(--blue); border:none; font-weight:600; white-space:nowrap; transition:opacity .15s; }
button:hover { opacity:.85; }
button.secondary { background:#2a2f3a; }
button.del { background:var(--red); }
button.small { padding:5px 9px; font-size:12px; }
table { width:100%; border-collapse:collapse; margin-top:4px; font-size:13px; }
th, td { padding:10px 8px; border-bottom:1px solid var(--border); text-align:right; }
th { color:var(--muted); font-weight:normal; font-size:12px; }
tr:hover td { background:#161a23; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; }
.badge.on { background:#14532d; color:var(--green); }
.badge.off { background:#450a0a; color:var(--red); }
.badge.warn { background:#451a03; color:var(--amber); }
.bar { width:100px; height:6px; border-radius:99px; background:#242833; overflow:hidden; display:inline-block; vertical-align:middle; margin-inline-start:6px; }
.bar-fill { height:100%; background:var(--blue); }
.bar-fill.warn { background:var(--amber); }
.bar-fill.danger { background:var(--red); }
.actions button { margin-inline-start:4px; }
.empty { text-align:center; color:var(--muted); padding:30px; }
.toast { position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:var(--green); color:#0b0d12; padding:10px 18px; border-radius:8px; font-size:13px; font-weight:600; opacity:0; transition:opacity .2s; pointer-events:none; }
.toast.show { opacity:1; }
</style>
</head>
<body>
<h1>پنل مدیریت کانفیگ VLESS</h1>
<div class="sub" id="domainInfo"></div>

<div class="card">
  <h3>ورود</h3>
  <div class="row">
    <input id="token" type="password" placeholder="Admin Token" style="max-width:260px">
    <button class="secondary" onclick="saveToken()">ذخیره و ورود</button>
  </div>
</div>

<div class="card">
  <h3>ساخت کانفیگ جدید</h3>
  <div class="row">
    <input id="name" placeholder="نام مشتری">
    <input id="traffic" type="number" min="0" placeholder="حجم (GB) — 0 = نامحدود">
    <input id="expires" type="date">
    <button onclick="createUser()">➕ ساخت</button>
  </div>
</div>

<div class="card">
  <h3>مدیریت IP‌های تمیز (برای دور زدن بلاک)</h3>
  <div class="row">
    <input id="ipInput" placeholder="IP یا چند IP (با اینتر/کاما/اسپیس جدا کن)" style="flex:2">
    <button onclick="addIps()">➕ افزودن</button>
  </div>
  <div id="ipList" style="margin-top:10px; font-size:12px;"></div>
</div>

<div class="card">
  <div class="row" style="justify-content:space-between; margin-bottom:12px;">
    <h3 style="margin:0">لیست کاربران</h3>
    <input id="search" placeholder="جستجو..." style="max-width:180px" oninput="renderTable()">
  </div>
  <table id="tbl">
    <thead><tr><th>نام</th><th>وضعیت</th><th>مصرف</th><th>انقضا</th><th>لینک</th><th></th></tr></thead>
    <tbody></tbody>
  </table>
  <div id="emptyState" class="empty" style="display:none">هنوز کاربری ساخته نشده</div>
</div>

<div class="toast" id="toast"></div>

<script>
let allUsers = [];
function getToken() { return localStorage.getItem('admin_token') || ''; }
function saveToken() { localStorage.setItem('admin_token', document.getElementById('token').value); load(); }
document.getElementById('token').value = getToken();
document.getElementById('domainInfo').textContent = 'دامنه سرور: ' + location.host;

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1800);
}

async function api(path, opts={}) {
  opts.headers = Object.assign({ 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' }, opts.headers || {});
  const res = await fetch(path, opts);
  if (!res.ok) {
    const txt = await res.text();
    showToast('خطا: ' + res.status);
    throw new Error(txt);
  }
  return res.json();
}

function subUrl(u) {
  return location.origin + '/sub/' + u.uuid;
}

let allIps = [];
async function loadIps() {
  try { allIps = await api('/api/ips'); } catch (e) { allIps = []; }
  renderIps();
}

function renderIps() {
  const box = document.getElementById('ipList');
  if (!Array.isArray(allIps) || allIps.length === 0) {
    box.innerHTML = '<span style="color:var(--muted)">هنوز IP‌ای اضافه نشده — بدون IP، لینک‌ها از خود دامنه سرور استفاده می‌کنن.</span>';
    return;
  }
  box.innerHTML = allIps.map(ip => \`
    <span style="display:inline-flex; align-items:center; gap:6px; background:#1a1e28; border:1px solid var(--border); border-radius:999px; padding:4px 10px; margin:3px; font-family:monospace;">
      \${ip.active ? '🟢' : '⚪'} \${ip.ip}
      <span style="cursor:pointer; color:var(--muted)" onclick="toggleIp(\${ip.id}, \${ip.active?0:1})" title="فعال/غیرفعال">⏻</span>
      <span style="cursor:pointer; color:var(--red)" onclick="delIp(\${ip.id})" title="حذف">✕</span>
    </span>\`).join('');
}

async function addIps() {
  const val = document.getElementById('ipInput').value;
  if (!val.trim()) return;
  try {
    await api('/api/ips', { method: 'POST', body: JSON.stringify({ ips: val }) });
    document.getElementById('ipInput').value = '';
    showToast('IP اضافه شد');
    loadIps();
  } catch (e) {}
}

async function toggleIp(id, active) {
  await api('/api/ips/' + id, { method: 'PATCH', body: JSON.stringify({ active }) });
  loadIps();
}

async function delIp(id) {
  await api('/api/ips/' + id, { method: 'DELETE' });
  loadIps();
}

function daysLeft(expiresAt) {
  if (!expiresAt) return null;
  const diff = expiresAt - Math.floor(Date.now()/1000);
  return Math.ceil(diff / 86400);
}

async function load() {
  try {
    allUsers = await api('/api/users');
  } catch (e) { allUsers = []; }
  renderTable();
}

function renderTable() {
  const q = (document.getElementById('search').value || '').toLowerCase();
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  const filtered = Array.isArray(allUsers) ? allUsers.filter(u => (u.name||'').toLowerCase().includes(q) || u.uuid.includes(q)) : [];

  document.getElementById('emptyState').style.display = filtered.length ? 'none' : 'block';

  for (const u of filtered) {
    const usedGb = u.traffic_used_bytes / 1024**3;
    const limitGb = u.traffic_limit_bytes / 1024**3;
    const pct = limitGb > 0 ? Math.min(100, (usedGb/limitGb)*100) : 0;
    const barClass = pct > 90 ? 'danger' : pct > 70 ? 'warn' : '';
    const usedTxt = usedGb.toFixed(2) + (limitGb > 0 ? ' / ' + limitGb.toFixed(2) + ' GB' : ' GB (نامحدود)');

    const dl = daysLeft(u.expires_at);
    let expiresTxt = '—';
    let expBadge = '';
    if (u.expires_at) {
      expiresTxt = new Date(u.expires_at * 1000).toLocaleDateString('fa-IR');
      if (dl < 0) expBadge = '<span class="badge off">منقضی</span>';
      else if (dl <= 3) expBadge = '<span class="badge warn">' + dl + ' روز مانده</span>';
    }

    const statusBadge = u.enabled
      ? (dl !== null && dl < 0 ? '<span class="badge off">منقضی</span>' : '<span class="badge on">فعال</span>')
      : '<span class="badge off">غیرفعال</span>';

    const tr = document.createElement('tr');
    tr.innerHTML = \`
      <td>\${u.name || '(بدون نام)'}</td>
      <td>\${statusBadge}</td>
      <td>\${usedTxt}\${limitGb>0 ? '<span class="bar"><span class="bar-fill '+barClass+'" style="width:'+pct+'%"></span></span>' : ''}</td>
      <td>\${expiresTxt} \${expBadge}</td>
      <td><button class="small secondary" onclick="copyLink('\${u.id}')">📋 کپی ساب‌اسکریپشن</button></td>
      <td class="actions">
        <button class="small secondary" onclick="toggleUser(\${u.id}, \${u.enabled ? 0 : 1})">\${u.enabled ? 'غیرفعال' : 'فعال'}</button>
        <button class="small secondary" onclick="resetTraffic(\${u.id})">ریست حجم</button>
        <button class="small del" onclick="delUser(\${u.id})">حذف</button>
      </td>\`;
    tbody.appendChild(tr);
  }
}

function copyLink(id) {
  const u = allUsers.find(x => x.id == id);
  if (!u) return;
  navigator.clipboard.writeText(subUrl(u));
  showToast('لینک ساب‌اسکریپشن کپی شد');
}

async function createUser() {
  const name = document.getElementById('name').value;
  const traffic_limit_gb = document.getElementById('traffic').value || 0;
  const expires_at = document.getElementById('expires').value || null;
  try {
    await api('/api/users', { method: 'POST', body: JSON.stringify({ name, traffic_limit_gb, expires_at }) });
    document.getElementById('name').value = '';
    document.getElementById('traffic').value = '';
    document.getElementById('expires').value = '';
    showToast('کانفیگ ساخته شد');
    load();
  } catch (e) {}
}

async function toggleUser(id, enabled) {
  await api('/api/users/' + id, { method: 'PATCH', body: JSON.stringify({ enabled }) });
  load();
}

async function resetTraffic(id) {
  await api('/api/users/' + id, { method: 'PATCH', body: JSON.stringify({ reset_traffic: true }) });
  showToast('حجم ریست شد');
  load();
}

async function delUser(id) {
  if (!confirm('حذف بشه؟')) return;
  await api('/api/users/' + id, { method: 'DELETE' });
  showToast('حذف شد');
  load();
}

load();
loadIps();
</script>
</body>
</html>`;
