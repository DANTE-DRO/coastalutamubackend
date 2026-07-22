/**
 * Utamu Agency - Mombasa Hookup Weekend Application
 * Backend server (Express + SQLite + Multer)
 *
 * Endpoints:
 *   POST /api/apply                  - submit an application (multipart/form-data)
 *   GET  /api/receipt/:ticket        - fetch receipt JSON by ticket
 *   GET  /api/receipt/:ticket/pdf    - download receipt as printable HTML
 *
 *   POST /admin/login                - password login
 *   POST /admin/logout               - logout
 *   GET  /admin/api/session          - check session
 *   GET  /admin/api/applications     - list all applications
 *   GET  /admin/api/applications/:id - single application detail
 *   GET  /admin/api/export.csv       - export all as CSV
 *   GET  /admin/api/download/:id/all - download all files for an application (zip)
 *   GET  /admin/api/file/:id/:field/:index - serve/download individual asset
 *   DELETE /admin/api/applications/:id - delete an application
 *
 *   GET  /admin                      - admin panel UI
 *   GET  /                           - health / landing
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const session = require('express-session');
const Database = require('better-sqlite3');
const archiver = require('archiver');

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '11utamu72';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// ---------- Paths ----------
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- Database ----------
const db = new Database(path.join(DATA_DIR, 'utamu.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    mpesa_number TEXT NOT NULL,
    referral_code TEXT,
    county TEXT NOT NULL,
    age INTEGER,
    gender TEXT,
    availability TEXT,
    languages TEXT,
    bio TEXT,
    ip TEXT,
    user_agent TEXT,
    profile_pics TEXT,
    cool_pics TEXT,
    nude_pics TEXT,
    nude_videos TEXT,
    confirm_share INTEGER,
    confirm_age INTEGER,
    confirm_guidelines INTEGER,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ---------- Middleware ----------
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 4 // 4 hours
  }
}));
app.use(express.static(PUBLIC_DIR));

// ---------- Multer (uploads) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const ticket = req.ticket || 'tmp';
    const dir = path.join(UPLOAD_DIR, ticket);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${file.fieldname}-${Date.now()}-${safe}`);
  }
});

const IMAGE_EXTS = /\.(jpe?g|png|gif|webp|bmp|heic|heif)$/i;
const VIDEO_EXTS = /\.(mp4|mov|m4v|webm|avi|mkv|3gp|3g2|ts|flv|wmv)$/i;
const fileFilter = (req, file, cb) => {
  const isImageField = ['profile_pics', 'cool_pics', 'nude_pics'].includes(file.fieldname);
  const isVideoField = file.fieldname === 'nude_videos';
  const mt = (file.mimetype || '').toLowerCase();
  const nm = file.originalname || '';
  if (isImageField) {
    const ok = mt.startsWith('image/') || IMAGE_EXTS.test(nm);
    if (!ok) return cb(new Error('Only images allowed for ' + file.fieldname));
  }
  if (isVideoField) {
    const ok = mt.startsWith('video/') || VIDEO_EXTS.test(nm) || mt === 'application/octet-stream';
    if (!ok) return cb(new Error('Only videos allowed for nude_videos'));
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 500 * 1024 * 1024, // 500MB per file (videos)
    files: 20
  }
}).fields([
  { name: 'profile_pics', maxCount: 2 },
  { name: 'cool_pics', maxCount: 3 },
  { name: 'nude_pics', maxCount: 3 },
  { name: 'nude_videos', maxCount: 3 }
]);

// Assign ticket BEFORE multer so uploads land in the right folder
function assignTicket(req, res, next) {
  const now = new Date();
  const stamp = now.getFullYear().toString().slice(-2)
    + String(now.getMonth() + 1).padStart(2, '0')
    + String(now.getDate()).padStart(2, '0');
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  req.ticket = `UTM-${stamp}-${rand}`;
  next();
}

// ---------- Public routes ----------
app.get('/', (req, res) => {
  res.json({
    service: 'Utamu Agency API',
    status: 'ok',
    admin: '/admin',
    time: new Date().toISOString()
  });
});

app.post('/api/apply', assignTicket, (req, res) => {
  upload(req, res, (err) => {
    if (err) {
      console.error('Upload error:', err.message);
      return res.status(400).json({ ok: false, error: err.message });
    }
    try {
      const b = req.body;
      const required = ['full_name', 'username', 'email', 'phone', 'mpesa_number', 'county'];
      for (const key of required) {
        if (!b[key] || !String(b[key]).trim()) {
          return res.status(400).json({ ok: false, error: `Field "${key}" is required` });
        }
      }
      if (!b.confirm_share || !b.confirm_age || !b.confirm_guidelines) {
        return res.status(400).json({ ok: false, error: 'All confirmation checkboxes are required' });
      }

      const files = req.files || {};
      const pack = (arr) => (arr || []).map(f => ({
        name: f.originalname,
        stored: f.filename,
        mime: f.mimetype,
        size: f.size
      }));

      const stmt = db.prepare(`
        INSERT INTO applications
          (ticket, full_name, username, email, phone, mpesa_number, referral_code, county,
           age, gender, availability, languages, bio, ip, user_agent,
           profile_pics, cool_pics, nude_pics, nude_videos,
           confirm_share, confirm_age, confirm_guidelines)
        VALUES (@ticket,@full_name,@username,@email,@phone,@mpesa_number,@referral_code,@county,
                @age,@gender,@availability,@languages,@bio,@ip,@user_agent,
                @profile_pics,@cool_pics,@nude_pics,@nude_videos,
                @confirm_share,@confirm_age,@confirm_guidelines)
      `);

      const info = stmt.run({
        ticket: req.ticket,
        full_name: b.full_name.trim(),
        username: b.username.trim(),
        email: b.email.trim(),
        phone: b.phone.trim(),
        mpesa_number: b.mpesa_number.trim(),
        referral_code: (b.referral_code || '').trim(),
        county: b.county.trim(),
        age: b.age ? parseInt(b.age, 10) : null,
        gender: b.gender || null,
        availability: b.availability || null,
        languages: b.languages || null,
        bio: b.bio || null,
        ip: req.ip,
        user_agent: req.get('user-agent') || '',
        profile_pics: JSON.stringify(pack(files.profile_pics)),
        cool_pics: JSON.stringify(pack(files.cool_pics)),
        nude_pics: JSON.stringify(pack(files.nude_pics)),
        nude_videos: JSON.stringify(pack(files.nude_videos)),
        confirm_share: 1,
        confirm_age: 1,
        confirm_guidelines: 1
      });

      res.json({
        ok: true,
        ticket: req.ticket,
        id: info.lastInsertRowid,
        message: 'Welcome to Utamu Agency. Our team will respond via our official email within 2 hours.'
      });
    } catch (e) {
      console.error('DB error:', e);
      res.status(500).json({ ok: false, error: 'Server error: ' + e.message });
    }
  });
});

// Receipt JSON
app.get('/api/receipt/:ticket', (req, res) => {
  const row = db.prepare('SELECT ticket, full_name, username, email, county, created_at FROM applications WHERE ticket = ?').get(req.params.ticket);
  if (!row) return res.status(404).json({ ok: false, error: 'Ticket not found' });
  res.json({ ok: true, receipt: row });
});

// Downloadable receipt (printable HTML)
app.get('/api/receipt/:ticket/pdf', (req, res) => {
  const row = db.prepare('SELECT * FROM applications WHERE ticket = ?').get(req.params.ticket);
  if (!row) return res.status(404).send('Ticket not found');
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Utamu Agency Receipt ${row.ticket}</title>
  <style>
    *{box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#0b0510;color:#fff;margin:0;padding:40px}
    .card{max-width:720px;margin:0 auto;background:linear-gradient(135deg,#1a0a24,#2d0f3a);border:1px solid #6b1f8f;border-radius:20px;padding:40px;box-shadow:0 30px 80px rgba(120,20,180,.4)}
    h1{margin:0 0 4px;color:#ff4d8d;letter-spacing:1px}
    .sub{color:#c9a3ff;margin-bottom:28px;font-size:14px}
    .ticket{background:#000;border:2px dashed #ff4d8d;padding:20px;border-radius:12px;text-align:center;margin:20px 0}
    .ticket .code{font-family:'Courier New',monospace;font-size:28px;color:#ffd166;letter-spacing:3px}
    table{width:100%;border-collapse:collapse;margin-top:20px}
    td{padding:10px 12px;border-bottom:1px solid #3a1550}
    td:first-child{color:#c9a3ff;width:40%}
    .stamp{margin-top:30px;text-align:center;font-size:12px;color:#8a6ba8}
    .btn-print{display:inline-block;margin-top:20px;padding:12px 24px;background:#ff4d8d;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:bold}
    @media print{.btn-print{display:none}body{background:#fff;color:#000}.card{border:2px solid #000;box-shadow:none}}
  </style></head>
  <body><div class="card">
    <h1>UTAMU AGENCY</h1>
    <div class="sub">Mombasa Hookup Weekend • Application Receipt</div>
    <div class="ticket">
      <div>YOUR TICKET NUMBER</div>
      <div class="code">${row.ticket}</div>
    </div>
    <table>
      <tr><td>Full Name</td><td>${escapeHtml(row.full_name)}</td></tr>
      <tr><td>Username</td><td>${escapeHtml(row.username)}</td></tr>
      <tr><td>Email</td><td>${escapeHtml(row.email)}</td></tr>
      <tr><td>Phone</td><td>${escapeHtml(row.phone)}</td></tr>
      <tr><td>County</td><td>${escapeHtml(row.county)}</td></tr>
      <tr><td>Submitted</td><td>${row.created_at} UTC</td></tr>
      <tr><td>Status</td><td>Pending Review</td></tr>
    </table>
    <p style="margin-top:26px;line-height:1.6;color:#e0c6ff">
      Welcome to Utamu Agency. Your application has been received. Our team will respond
      to you via our <b>official email</b> within <b>2 hours</b>. Most of our clients are
      based in the Middle East and your information is kept strictly private.
    </p>
    <div class="stamp">This receipt was issued by Utamu Agency • Confidential</div>
    <button class="btn-print" onclick="window.print()">Print / Save as PDF</button>
  </div></body></html>`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Disposition', `inline; filename="utamu-receipt-${row.ticket}.html"`);
  res.send(html);
});

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ---------- Admin ----------
function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  if (req.path.startsWith('/admin/api')) return res.status(401).json({ ok: false, error: 'unauthorized' });
  res.redirect('/admin/login.html');
}

app.post('/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) {
    req.session.admin = true;
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false, error: 'Invalid password' });
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/admin/api/session', (req, res) => {
  res.json({ ok: true, authenticated: !!(req.session && req.session.admin) });
});

app.get('/admin/api/applications', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM applications ORDER BY id DESC').all();
  const parsed = rows.map(r => ({
    ...r,
    profile_pics: safeJson(r.profile_pics),
    cool_pics: safeJson(r.cool_pics),
    nude_pics: safeJson(r.nude_pics),
    nude_videos: safeJson(r.nude_videos)
  }));
  res.json({ ok: true, applications: parsed, total: parsed.length });
});

app.get('/admin/api/applications/:id', requireAdmin, (req, res) => {
  const r = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ ok: false });
  res.json({
    ok: true,
    application: {
      ...r,
      profile_pics: safeJson(r.profile_pics),
      cool_pics: safeJson(r.cool_pics),
      nude_pics: safeJson(r.nude_pics),
      nude_videos: safeJson(r.nude_videos)
    }
  });
});

app.delete('/admin/api/applications/:id', requireAdmin, (req, res) => {
  const r = db.prepare('SELECT ticket FROM applications WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).json({ ok: false });
  db.prepare('DELETE FROM applications WHERE id = ?').run(req.params.id);
  // remove files
  const dir = path.join(UPLOAD_DIR, r.ticket);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  res.json({ ok: true });
});

// Serve individual asset (image or video). Supports Range for videos so <video> can seek.
app.get('/admin/api/file/:id/:field/:index', requireAdmin, (req, res) => {
  const { id, field, index } = req.params;
  const allowed = ['profile_pics', 'cool_pics', 'nude_pics', 'nude_videos'];
  if (!allowed.includes(field)) return res.status(400).send('bad field');
  const row = db.prepare(`SELECT ticket, ${field} AS list FROM applications WHERE id = ?`).get(id);
  if (!row) return res.status(404).send('not found');
  const arr = safeJson(row.list);
  const item = arr[Number(index)];
  if (!item) return res.status(404).send('file not found');
  const abs = path.join(UPLOAD_DIR, row.ticket, item.stored);
  if (!fs.existsSync(abs)) return res.status(404).send('missing');

  if (req.query.download === '1') {
    return res.download(abs, item.name);
  }

  // Range support for video
  const stat = fs.statSync(abs);
  const range = req.headers.range;
  if (range && item.mime && item.mime.startsWith('video/')) {
    const parts = range.replace(/bytes=/, '').split('-');
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
    const chunk = (end - start) + 1;
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${stat.size}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': chunk,
      'Content-Type': item.mime
    });
    fs.createReadStream(abs, { start, end }).pipe(res);
  } else {
    res.setHeader('Content-Type', item.mime || 'application/octet-stream');
    res.setHeader('Content-Length', stat.size);
    fs.createReadStream(abs).pipe(res);
  }
});

// Download all files for a single application as a zip
app.get('/admin/api/download/:id/all', requireAdmin, (req, res) => {
  const r = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!r) return res.status(404).send('not found');
  const dir = path.join(UPLOAD_DIR, r.ticket);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${r.ticket}-${r.username || 'applicant'}.zip"`);
  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', err => { console.error(err); res.end(); });
  archive.pipe(res);
  // Add JSON summary
  archive.append(JSON.stringify(r, null, 2), { name: `${r.ticket}-info.json` });
  if (fs.existsSync(dir)) {
    archive.directory(dir, 'media');
  }
  archive.finalize();
});

// Export all applications as CSV
app.get('/admin/api/export.csv', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM applications ORDER BY id DESC').all();
  const headers = ['id','ticket','full_name','username','email','phone','mpesa_number','referral_code','county','age','gender','availability','languages','status','created_at'];
  const esc = v => `"${String(v == null ? '' : v).replace(/"/g,'""')}"`;
  const csv = [headers.join(',')].concat(rows.map(r => headers.map(h => esc(r[h])).join(','))).join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="utamu-applications.csv"');
  res.send(csv);
});

function safeJson(s) {
  try { return JSON.parse(s || '[]'); } catch { return []; }
}

// Admin UI routes
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});
app.get('/admin/login.html', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ ok: false, error: err.message });
});

app.listen(PORT, () => {
  console.log(`\n🌹 Utamu Agency backend running on port ${PORT}`);
  console.log(`   Admin panel: http://localhost:${PORT}/admin`);
  console.log(`   Admin password: ${ADMIN_PASSWORD}\n`);
});
