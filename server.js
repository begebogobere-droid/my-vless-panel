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

// ---------------- تشخیص خودکار کشور سرور (برای پرچم و لیبل لوکیشن) ----------------

let serverLocation = { countryCode: null, countryName: null, flag: "🌐" };

function countryCodeToFlag(cc) {
  if (!cc || cc.length !== 2) return "🌐";
  const codePoints = cc.toUpperCase().split("").map((c) => 0x1f1e6 - 65 + c.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

async function detectServerLocation() {
  try {
    const res = await fetch("https://ipapi.co/json/", { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error("bad status " + res.status);
    const data = await res.json();
    if (data && data.country_code) {
      serverLocation = {
        countryCode: data.country_code,
        countryName: data.country_name || data.country_code,
        flag: countryCodeToFlag(data.country_code),
      };
      console.log("Server location detected:", serverLocation);
      return;
    }
    throw new Error("no country_code in response");
  } catch (err) {
    console.error("Location detection failed, retrying with fallback API:", err.message);
    try {
      const res2 = await fetch("https://ipwho.is/", { signal: AbortSignal.timeout(5000) });
      const data2 = await res2.json();
      if (data2 && data2.country_code) {
        serverLocation = {
          countryCode: data2.country_code,
          countryName: data2.country || data2.country_code,
          flag: countryCodeToFlag(data2.country_code),
        };
        console.log("Server location detected (fallback):", serverLocation);
      }
    } catch (err2) {
      console.error("Fallback location detection also failed:", err2.message);
    }
  }
}

detectServerLocation();
// هر ۶ ساعت یه‌بار دوباره چک کن (چون IP سرور روی Railway ممکنه عوض بشه)
setInterval(detectServerLocation, 6 * 60 * 60 * 1000);

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
  const auth = (req.headers["authorization"] || "").trim();
  return auth === `Bearer ${ADMIN_TOKEN.trim()}`;
}

// ---------------- Login ----------------

app.post("/api/login", (req, res) => {
  const body = req.body || {};
  const submitted = (body.token || "").toString().trim();
  if (submitted === ADMIN_TOKEN.trim()) {
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, error: "پسورد اشتباه است" });
});

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
  // ورودی حالا بر اساس مگابایت (MB) هست تا بشه مقادیر کمتر از ۱ گیگ (مثل ۱۰۰ یا ۲۰۰ مگ) هم زد
  const trafficLimit = Math.round(Number(body.traffic_limit_mb || 0) * 1024 * 1024);
  const expiresAt = body.expires_at ? Math.floor(new Date(body.expires_at).getTime() / 1000) : null;

  db.prepare(
    `INSERT INTO users (uuid, name, traffic_limit_bytes, expires_at, enabled) VALUES (?, ?, ?, ?, 1)`
  ).run(uuid, name, trafficLimit, expiresAt);

  res.json({ uuid, name, traffic_limit_mb: body.traffic_limit_mb || 0, expires_at: body.expires_at || null });
});

app.patch("/api/users/:id", (req, res) => {
  if (!checkAuth(req)) return res.status(401).json({ error: "unauthorized" });
  const id = req.params.id;
  const body = req.body || {};
  const fields = [];
  const values = [];

  if (body.name !== undefined) { fields.push("name = ?"); values.push(body.name); }
  if (body.traffic_limit_mb !== undefined) {
    fields.push("traffic_limit_bytes = ?");
    values.push(Math.round(Number(body.traffic_limit_mb) * 1024 * 1024));
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

function fmtBytes(n) {
  if (n >= 1024 ** 3) return (n / 1024 ** 3).toFixed(2) + " GB";
  if (n >= 1024 ** 2) return (n / 1024 ** 2).toFixed(0) + " MB";
  return n + " B";
}

app.get("/sub/:uuid", (req, res) => {
  const uuid = req.params.uuid;
  const user = db.prepare("SELECT * FROM users WHERE uuid = ?").get(uuid);
  if (!user) return res.status(404).send("not found");

  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const flag = serverLocation.flag || "🌐";
  const name = user.name || "user";

  const nowSec = Math.floor(Date.now() / 1000);
  const used = user.traffic_used_bytes || 0;
  const limit = user.traffic_limit_bytes || 0;
  const isExpired = user.expires_at && user.expires_at < nowSec;
  const isQuotaExceeded = limit > 0 && used >= limit;
  const isBlocked = !user.enabled || isExpired || isQuotaExceeded;

  let allLinks;

  if (isBlocked) {
    // به‌جای کانفیگ واقعی، فقط یه پیام وضعیت برمی‌گردونه که کل چیزهای قبلی رو جای خودش می‌گیره
    let reason;
    if (isQuotaExceeded) reason = "🚫 حجم کانفیگ شما به اتمام رسیده";
    else if (isExpired) reason = "🚫 کانفیگ شما منقضی شده";
    else reason = "🚫 کانفیگ شما غیرفعال شده";

    allLinks = [
      `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=none&type=tcp#${encodeURIComponent(reason)}`,
    ];
  } else {
    const ips = db.prepare("SELECT ip, note FROM clean_ips WHERE active = 1 ORDER BY created_at DESC").all();
    const encName = encodeURIComponent(`${flag} ${name}`);

    // --- کانفیگ‌های اصلی VLESS ---
    let mainLinks;
    if (ips.length === 0) {
      mainLinks = [`vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2F#${encName}`];
    } else {
      mainLinks = ips.map((row) => {
        const label = encodeURIComponent(`${flag} ${name}-${row.note || row.ip}`);
        return `vless://${uuid}@${row.ip}:443?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2F#${label}`;
      });
    }

    // --- دو کانفیگ اطلاعاتی (به‌عنوان entry غیرقابل اتصال، فقط برای نمایش وضعیت در اپ) ---
    let timeInfoLabel;
    if (user.expires_at) {
      const daysLeft = Math.ceil((user.expires_at - nowSec) / 86400);
      timeInfoLabel = `⏳ زمان باقی‌مانده： ${daysLeft} روز`;
    } else {
      timeInfoLabel = `⏳ زمان باقی‌مانده： بدون انقضا`;
    }

    const volInfoLabel = limit > 0
      ? `📊 حجم： ${fmtBytes(used)} / ${fmtBytes(limit)}`
      : `📊 حجم مصرفی： ${fmtBytes(used)} (نامحدود)`;

    const infoLinks = [
      `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=none&type=tcp#${encodeURIComponent(timeInfoLabel)}`,
      `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=none&type=tcp#${encodeURIComponent(volInfoLabel)}`,
    ];

    allLinks = [...infoLinks, ...mainLinks];
  }

  const body = allLinks.join("\n");
  const b64 = Buffer.from(body, "utf8").toString("base64");

  // هدر استاندارد subscription-userinfo — اپ‌هایی مثل Happ/v2rayNG/NekoBox حجم و انقضا رو از این هدر می‌خونن
  const userinfoParts = [`upload=0`, `download=${used}`, `total=${limit > 0 ? limit : 0}`];
  if (user.expires_at) userinfoParts.push(`expire=${user.expires_at}`);
  res.set("subscription-userinfo", userinfoParts.join("; "));
  res.set("profile-update-interval", "12");

  // اگه درخواست مستقیم از مرورگر باشه (نه از اپ کلاینت) یه صفحه خوانا با دکمه کپی نشون بده
  const accept = req.headers["accept"] || "";
  const ua = req.headers["user-agent"] || "";
  const looksLikeBrowser = accept.includes("text/html") && !/happ|v2ray|nekobox|clash|shadowrocket|streisand/i.test(ua);

  if (looksLikeBrowser) {
    const linksHtml = allLinks.map((l) => {
      const label = decodeURIComponent(l.split("#")[1] || "");
      return `<div class="linkrow"><div class="linklabel">${label}</div><textarea readonly onclick="this.select()">${l}</textarea><button onclick="copyLine(this)" data-link="${encodeURIComponent(l)}">📋 کپی</button></div>`;
    }).join("");

    const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>کانفیگ شما</title>
<style>
body{font-family:Tahoma,sans-serif;background:#0b0d12;color:#e8eaed;padding:16px;margin:0}
h2{font-size:16px;margin:0 0 14px}
.linkrow{background:#12151c;border:1px solid #242833;border-radius:10px;padding:12px;margin-bottom:12px}
.linklabel{font-size:13px;color:#8b91a0;margin-bottom:6px}
textarea{width:100%;background:#1a1e28;color:#e8eaed;border:1px solid #242833;border-radius:6px;padding:8px;font-size:11px;font-family:monospace;resize:none;height:60px;box-sizing:border-box}
button{margin-top:8px;padding:8px 14px;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#22c55e;color:#0b0d12;padding:10px 18px;border-radius:8px;font-size:13px;font-weight:600;opacity:0;transition:opacity .2s}
.toast.show{opacity:1}
</style></head>
<body>
<h2>📄 کانفیگ‌های شما (${name})</h2>
${linksHtml}
<div class="toast" id="toast">کپی شد</div>
<script>
function copyLine(btn){
  const link = decodeURIComponent(btn.getAttribute('data-link'));
  navigator.clipboard.writeText(link).then(()=>{
    const t = document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'), 1500);
  });
}
</script>
</body></html>`;
    return res.set("content-type", "text/html; charset=utf-8").send(html);
  }

  res.set("content-disposition", `attachment; filename="${encodeURIComponent(name) || "config"}"`);
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
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>پنل مدیریت کانفیگ</title>
<style>
:root {
  --bg:#0b0d12; --panel:#12151c; --border:#242833; --text:#e8eaed; --muted:#8b91a0;
  --blue:#3b82f6; --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
}
* { box-sizing:border-box; }
html, body { max-width:100%; overflow-x:hidden; }
body { font-family: Vazirmatn, Tahoma, sans-serif; background:var(--bg); color:var(--text); padding:14px; margin:0; }
h1 { font-size:17px; margin:0 0 4px; }
.sub { color:var(--muted); font-size:12px; margin-bottom:16px; word-break:break-all; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px; margin-bottom:14px; }
.card h3 { margin:0 0 12px; font-size:13px; color:var(--muted); font-weight:normal; }
.row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
input, button, select { padding:9px 12px; border-radius:8px; border:1px solid var(--border); background:#1a1e28; color:var(--text); font-size:13px; }
input { min-width:0; width:100%; flex:1 1 140px; }
button { cursor:pointer; background:var(--blue); border:none; font-weight:600; white-space:nowrap; transition:opacity .15s; }
button:hover { opacity:.85; }
button.secondary { background:#2a2f3a; }
button.del { background:var(--red); }
button.small { padding:6px 10px; font-size:12px; }
button.full { width:100%; }

/* جدول روی موبایل به‌صورت کارت نمایش داده می‌شه */
table { width:100%; border-collapse:collapse; margin-top:4px; font-size:13px; }
th { display:none; }
tr { display:block; border:1px solid var(--border); border-radius:10px; margin-bottom:10px; padding:10px; background:#0f1218; }
td { display:flex; justify-content:space-between; align-items:center; gap:8px; padding:6px 2px; border:none; text-align:right; }
td:before { content: attr(data-label); color:var(--muted); font-size:11px; flex-shrink:0; }
td.actions { flex-wrap:wrap; justify-content:flex-start; }
td.actions:before { display:none; }
td.actions button { margin:2px; }

@media (min-width: 720px) {
  body { padding:20px; }
  h1 { font-size:19px; }
  input { min-width:140px; }
  table { }
  th { display:table-cell; color:var(--muted); font-weight:normal; font-size:12px; padding:10px 8px; border-bottom:1px solid var(--border); text-align:right; }
  tr { display:table-row; border:none; margin:0; padding:0; background:transparent; }
  tr:hover td { background:#161a23; }
  td { display:table-cell; padding:10px 8px; border-bottom:1px solid var(--border); }
  td:before { content:none; }
}

.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; }
.badge.on { background:#14532d; color:var(--green); }
.badge.off { background:#450a0a; color:var(--red); }
.badge.warn { background:#451a03; color:var(--amber); }
.bar { width:80px; height:6px; border-radius:99px; background:#242833; overflow:hidden; display:inline-block; vertical-align:middle; margin-inline-start:6px; }
.bar-fill { height:100%; background:var(--blue); }
.bar-fill.warn { background:var(--amber); }
.bar-fill.danger { background:var(--red); }
.empty { text-align:center; color:var(--muted); padding:30px; }
.toast { position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:var(--green); color:#0b0d12; padding:10px 18px; border-radius:8px; font-size:13px; font-weight:600; opacity:0; transition:opacity .2s; pointer-events:none; max-width:90vw; text-align:center; z-index:50; }
.toast.show { opacity:1; }

/* صفحه لاگین */
#loginScreen { position:fixed; inset:0; background:var(--bg); display:flex; align-items:center; justify-content:center; padding:20px; z-index:100; }
#loginScreen .box { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:24px; width:100%; max-width:340px; text-align:center; }
#loginScreen h2 { margin:0 0 6px; font-size:16px; }
#loginScreen p { color:var(--muted); font-size:12px; margin:0 0 16px; }
#loginScreen input { margin-bottom:10px; text-align:center; }
#loginError { color:var(--red); font-size:12px; min-height:16px; margin-top:8px; }
#appRoot { display:none; }
</style>
</head>
<body>

<div id="loginScreen">
  <div class="box">
    <h2>🔒 ورود به پنل</h2>
    <p>برای دسترسی به پنل، رمز ادمین را وارد کنید</p>
    <input id="loginToken" type="password" placeholder="Admin Token" onkeydown="if(event.key==='Enter') doLogin()">
    <button class="full" onclick="doLogin()">ورود</button>
    <div id="loginError"></div>
  </div>
</div>

<div id="appRoot">
<h1>پنل مدیریت کانفیگ VLESS</h1>
<div class="sub" id="domainInfo"></div>

<div class="card">
  <h3>ساخت کانفیگ جدید</h3>
  <div class="row">
    <input id="name" placeholder="نام مشتری">
    <input id="traffic" type="number" min="0" step="1" placeholder="حجم (مگابایت) — 0 = نامحدود">
    <input id="expires" type="date">
    <button class="full" onclick="createUser()">➕ ساخت</button>
  </div>
</div>

<div class="card">
  <h3>مدیریت IP‌های تمیز (برای دور زدن بلاک)</h3>
  <div class="row">
    <input id="ipInput" placeholder="IP یا چند IP (با اینتر/کاما/اسپیس جدا کن)">
    <button class="full" onclick="addIps()">➕ افزودن</button>
  </div>
  <div id="ipList" style="margin-top:10px; font-size:12px;"></div>
</div>

<div class="card">
  <div class="row" style="justify-content:space-between; margin-bottom:12px;">
    <h3 style="margin:0">لیست کاربران</h3>
    <input id="search" placeholder="جستجو..." oninput="renderTable()">
  </div>
  <table id="tbl">
    <thead><tr><th>نام</th><th>وضعیت</th><th>مصرف</th><th>انقضا</th><th>لینک</th><th></th></tr></thead>
    <tbody></tbody>
  </table>
  <div id="emptyState" class="empty" style="display:none">هنوز کاربری ساخته نشده</div>
</div>
</div>

<div class="toast" id="toast"></div>

<script>
let allUsers = [];

function getToken() { return sessionStorage.getItem('admin_token') || ''; }
function setToken(t) { sessionStorage.setItem('admin_token', t); }
function clearToken() { sessionStorage.removeItem('admin_token'); }

async function doLogin() {
  const val = document.getElementById('loginToken').value.trim();
  const errBox = document.getElementById('loginError');
  errBox.textContent = '';
  if (!val) return;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: val })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      setToken(val);
      showApp();
    } else {
      errBox.textContent = 'رمز اشتباه است';
    }
  } catch (e) {
    errBox.textContent = 'خطا در ارتباط با سرور';
  }
}

function showApp() {
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('appRoot').style.display = 'block';
  document.getElementById('domainInfo').textContent = 'دامنه سرور: ' + location.host;
  load();
  loadIps();
}

// موقع بازکردن صفحه، اگه توکن ذخیره‌شده معتبره مستقیم برو تو، وگرنه فرم لاگین بمونه
(async function initAuth() {
  const t = getToken();
  if (!t) return;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: t })
    });
    const data = await res.json();
    if (res.ok && data.ok) showApp();
    else clearToken();
  } catch (e) {}
})();

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1800);
}

async function api(path, opts={}) {
  opts.headers = Object.assign({ 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' }, opts.headers || {});
  const res = await fetch(path, opts);
  if (res.status === 401) {
    clearToken();
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('appRoot').style.display = 'none';
    showToast('نشست منقضی شد، دوباره وارد شوید');
    throw new Error('unauthorized');
  }
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

function fmtMbGb(bytes) {
  const mb = bytes / 1024**2;
  if (mb >= 1024) return (mb/1024).toFixed(2) + ' GB';
  return mb.toFixed(0) + ' MB';
}

function renderTable() {
  const q = (document.getElementById('search').value || '').toLowerCase();
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  const filtered = Array.isArray(allUsers) ? allUsers.filter(u => (u.name||'').toLowerCase().includes(q) || u.uuid.includes(q)) : [];

  document.getElementById('emptyState').style.display = filtered.length ? 'none' : 'block';

  for (const u of filtered) {
    const usedBytes = u.traffic_used_bytes || 0;
    const limitBytes = u.traffic_limit_bytes || 0;
    const pct = limitBytes > 0 ? Math.min(100, (usedBytes/limitBytes)*100) : 0;
    const barClass = pct > 90 ? 'danger' : pct > 70 ? 'warn' : '';
    const usedTxt = fmtMbGb(usedBytes) + (limitBytes > 0 ? ' / ' + fmtMbGb(limitBytes) : ' (نامحدود)');

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
      <td data-label="نام">\${u.name || '(بدون نام)'}</td>
      <td data-label="وضعیت">\${statusBadge}</td>
      <td data-label="مصرف">\${usedTxt}\${limitBytes>0 ? '<span class="bar"><span class="bar-fill '+barClass+'" style="width:'+pct+'%"></span></span>' : ''}</td>
      <td data-label="انقضا">\${expiresTxt} \${expBadge}</td>
      <td data-label="لینک"><button class="small secondary" onclick="copyLink('\${u.id}')">📋 کپی ساب‌اسکریپشن</button></td>
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
  const traffic_limit_mb = document.getElementById('traffic').value || 0;
  const expires_at = document.getElementById('expires').value || null;
  try {
    await api('/api/users', { method: 'POST', body: JSON.stringify({ name, traffic_limit_mb, expires_at }) });
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
</script>
</body>
</html>`;
