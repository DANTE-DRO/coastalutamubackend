/**
 * Utamu Agency - Backend Server
 * Node.js + Express + SQLite
 * Deployable to Render.com Free Tier
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const archiver = require('archiver');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;

// ============ CONFIGURATION ============
const JWT_SECRET = process.env.JWT_SECRET || 'utamu-agency-super-secret-key-change-in-prod-2026';
const ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD || '11utamu72';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';

// On Render free tier, persistent disk is optional. We use local uploads dir.
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'utamu.db');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ============ MIDDLEWARE ============
app.use(cors({ origin: '*', credentials: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve uploaded files (protected via token query param for security)
app.use('/uploads', (req, res, next) => {
  const token = req.query.token;
  if (!token) return res.status(401).json({ error: 'Token required' });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}, express.static(UPLOAD_DIR));

// Rate limiter for submissions
const submitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many submissions from this IP, please try again later.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, please try again later.' }
});

// ============ DATABASE SETUP ============
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    ticket_number TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    mpesa_number TEXT NOT NULL,
    referral_code TEXT,
    county TEXT NOT NULL,
    username TEXT NOT NULL,
    age_confirmed INTEGER NOT NULL,
    guidelines_confirmed INTEGER NOT NULL,
    info_sharing_confirmed INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    ip_address TEXT,
    user_agent TEXT,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS media_files (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL,
    file_type TEXT NOT NULL,
    category TEXT NOT NULL,
    original_name TEXT,
    stored_name TEXT NOT NULL,
    mime_type TEXT,
    file_size INTEGER,
    duration REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_app_ticket ON applications(ticket_number);
  CREATE INDEX IF NOT EXISTS idx_media_app ON media_files(application_id);
`);

// ============ MULTER (FILE UPLOAD) ============
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const appDir = path.join(UPLOAD_DIR, req.applicationId || 'temp');
    if (!fs.existsSync(appDir)) fs.mkdirSync(appDir, { recursive: true });
    cb(null, appDir);
  },
  filename: (req, file, cb) => {
    const unique = uuidv4();
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${unique}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB per file
  fileFilter: (req, file, cb) => {
    const allowedImage = /jpeg|jpg|png|webp|gif|image/i;
    const allowedVideoMime = /mp4|mov|avi|mkv|webm|quicktime|video|octet-stream/i;
    const allowedVideoExt = /\.(mp4|mov|avi|mkv|webm|m4v|3gp|flv|wmv)$/i;
    const isImage = file.fieldname.includes('picture') || file.fieldname.includes('profile');
    const isVideo = file.fieldname.includes('video');

    if (isImage && (allowedImage.test(file.mimetype) || /\.(jpg|jpeg|png|webp|gif)$/i.test(file.originalname))) {
      return cb(null, true);
    }
    if (isVideo && (allowedVideoMime.test(file.mimetype) || allowedVideoExt.test(file.originalname))) {
      return cb(null, true);
    }
    cb(new Error(`Invalid file type for ${file.fieldname}: ${file.mimetype} (${file.originalname})`));
  }
});

// Attach applicationId before multer processes files
const prepareUpload = (req, res, next) => {
  req.applicationId = uuidv4();
  next();
};

const uploadFields = upload.fields([
  { name: 'profile_pictures', maxCount: 2 },
  { name: 'cool_pictures', maxCount: 3 },
  { name: 'nude_pictures', maxCount: 3 },
  { name: 'nude_videos', maxCount: 3 }
]);

// ============ AUTH MIDDLEWARE ============
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.isAdmin) return res.status(403).json({ error: 'Not authorized' });
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// ============ HELPER FUNCTIONS ============
function generateTicket() {
  const prefix = 'UTM';
  const timestamp = Date.now().toString().slice(-6);
  const random = Math.floor(Math.random() * 9000) + 1000;
  return `${prefix}-${timestamp}-${random}`;
}

// ============ ROUTES ============

// Health check
app.get('/', (req, res) => {
  res.json({
    service: 'Utamu Agency API',
    status: 'running',
    version: '1.0.0',
    endpoints: ['/api/submit', '/api/admin/login', '/api/admin/applications']
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============ APPLICATION SUBMISSION ============
app.post('/api/submit', submitLimiter, prepareUpload, (req, res) => {
  uploadFields(req, res, (err) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(400).json({ error: err.message });
    }

    try {
      const {
        full_name, email, phone, mpesa_number, referral_code,
        county, username, age_confirmed, guidelines_confirmed, info_sharing_confirmed
      } = req.body;

      // Validation
      if (!full_name || !email || !phone || !mpesa_number || !county || !username) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      if (!/^\S+@\S+\.\S+$/.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }

      if (age_confirmed !== 'true' || guidelines_confirmed !== 'true' || info_sharing_confirmed !== 'true') {
        return res.status(400).json({ error: 'All confirmations must be checked' });
      }

      const files = req.files || {};
      const profilePics = files.profile_pictures || [];
      const coolPics = files.cool_pictures || [];
      const nudePics = files.nude_pictures || [];
      const nudeVids = files.nude_videos || [];

      if (profilePics.length < 2) return res.status(400).json({ error: 'Please upload exactly 2 profile pictures' });
      if (coolPics.length < 3) return res.status(400).json({ error: 'Please upload exactly 3 cool pictures' });
      if (nudePics.length < 3) return res.status(400).json({ error: 'Please upload exactly 3 nude pictures' });
      if (nudeVids.length < 3) return res.status(400).json({ error: 'Please upload exactly 3 nude videos' });

      const applicationId = req.applicationId;
      const ticket = generateTicket();
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'] || '';

      // Insert application
      const insertApp = db.prepare(`
        INSERT INTO applications (
          id, ticket_number, full_name, email, phone, mpesa_number, referral_code,
          county, username, age_confirmed, guidelines_confirmed, info_sharing_confirmed,
          ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      insertApp.run(
        applicationId, ticket, full_name, email, phone, mpesa_number,
        referral_code || null, county, username, 1, 1, 1, ip, userAgent
      );

      // Insert media files
      const insertMedia = db.prepare(`
        INSERT INTO media_files (id, application_id, file_type, category, original_name, stored_name, mime_type, file_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const saveFiles = (fileList, fileType, category) => {
        fileList.forEach(f => {
          insertMedia.run(uuidv4(), applicationId, fileType, category, f.originalname, f.filename, f.mimetype, f.size);
        });
      };

      saveFiles(profilePics, 'image', 'profile');
      saveFiles(coolPics, 'image', 'cool');
      saveFiles(nudePics, 'image', 'nude');
      saveFiles(nudeVids, 'video', 'nude');

      res.json({
        success: true,
        ticket_number: ticket,
        application_id: applicationId,
        message: 'Application submitted successfully',
        submitted_at: new Date().toISOString()
      });
    } catch (error) {
      console.error('Submit error:', error);
      res.status(500).json({ error: 'Server error: ' + error.message });
    }
  });
});

// Get receipt (public, by ticket number)
app.get('/api/receipt/:ticket', (req, res) => {
  const row = db.prepare(`
    SELECT ticket_number, full_name, email, username, county, submitted_at, status
    FROM applications WHERE ticket_number = ?
  `).get(req.params.ticket);
  if (!row) return res.status(404).json({ error: 'Ticket not found' });
  res.json(row);
});

// ============ ADMIN ROUTES ============
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD_PLAIN) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username, isAdmin: true }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ success: true, token, expires_in: '24h' });
});

app.get('/api/admin/applications', authenticateAdmin, (req, res) => {
  const apps = db.prepare(`
    SELECT * FROM applications ORDER BY submitted_at DESC
  `).all();

  const enriched = apps.map(a => {
    const media = db.prepare('SELECT * FROM media_files WHERE application_id = ?').all(a.id);
    return { ...a, media };
  });
  res.json({ count: enriched.length, applications: enriched });
});

app.get('/api/admin/application/:id', authenticateAdmin, (req, res) => {
  const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!app) return res.status(404).json({ error: 'Not found' });
  const media = db.prepare('SELECT * FROM media_files WHERE application_id = ?').all(app.id);
  res.json({ ...app, media });
});

// Serve a media file (admin only)
app.get('/api/admin/media/:mediaId', authenticateAdmin, (req, res) => {
  const media = db.prepare('SELECT * FROM media_files WHERE id = ?').get(req.params.mediaId);
  if (!media) return res.status(404).json({ error: 'Media not found' });
  const filePath = path.join(UPLOAD_DIR, media.application_id, media.stored_name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing' });

  const download = req.query.download === '1';
  if (download) {
    return res.download(filePath, media.original_name || media.stored_name);
  }
  res.setHeader('Content-Type', media.mime_type);
  fs.createReadStream(filePath).pipe(res);
});

// Get a signed short-lived URL for direct browser access to a media file
app.get('/api/admin/media-url/:mediaId', authenticateAdmin, (req, res) => {
  const media = db.prepare('SELECT * FROM media_files WHERE id = ?').get(req.params.mediaId);
  if (!media) return res.status(404).json({ error: 'Media not found' });
  const token = jwt.sign({ isAdmin: true, mediaId: media.id }, JWT_SECRET, { expiresIn: '1h' });
  const url = `/uploads/${media.application_id}/${media.stored_name}?token=${token}`;
  res.json({ url, mime_type: media.mime_type });
});

// Export all applications as CSV
app.get('/api/admin/export/csv', authenticateAdmin, (req, res) => {
  const apps = db.prepare('SELECT * FROM applications ORDER BY submitted_at DESC').all();
  const header = 'Ticket,Full Name,Email,Phone,Mpesa,Referral,County,Username,Status,Submitted At\n';
  const rows = apps.map(a =>
    [a.ticket_number, a.full_name, a.email, a.phone, a.mpesa_number,
     a.referral_code || '', a.county, a.username, a.status, a.submitted_at]
    .map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')
  ).join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="utamu-applications-${Date.now()}.csv"`);
  res.send(header + rows);
});

// Download entire application (info + media) as ZIP
app.get('/api/admin/download/:id', authenticateAdmin, (req, res) => {
  const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!app) return res.status(404).json({ error: 'Not found' });
  const media = db.prepare('SELECT * FROM media_files WHERE application_id = ?').all(app.id);

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${app.ticket_number}.zip"`);

  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', err => res.status(500).send({ error: err.message }));
  archive.pipe(res);

  const info = JSON.stringify({ ...app, media }, null, 2);
  archive.append(info, { name: 'application_info.json' });

  media.forEach(m => {
    const filePath = path.join(UPLOAD_DIR, app.id, m.stored_name);
    if (fs.existsSync(filePath)) {
      archive.file(filePath, { name: `${m.category}/${m.original_name || m.stored_name}` });
    }
  });

  archive.finalize();
});

// Delete application
app.delete('/api/admin/application/:id', authenticateAdmin, (req, res) => {
  const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!app) return res.status(404).json({ error: 'Not found' });

  db.prepare('DELETE FROM media_files WHERE application_id = ?').run(app.id);
  db.prepare('DELETE FROM applications WHERE id = ?').run(app.id);

  const appDir = path.join(UPLOAD_DIR, app.id);
  if (fs.existsSync(appDir)) fs.rmSync(appDir, { recursive: true, force: true });

  res.json({ success: true });
});

// Update status
app.patch('/api/admin/application/:id', authenticateAdmin, (req, res) => {
  const { status } = req.body;
  const allowed = ['pending', 'approved', 'rejected', 'contacted'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  db.prepare('UPDATE applications SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ success: true });
});

// Stats
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as c FROM applications').get().c;
  const pending = db.prepare("SELECT COUNT(*) as c FROM applications WHERE status='pending'").get().c;
  const approved = db.prepare("SELECT COUNT(*) as c FROM applications WHERE status='approved'").get().c;
  const rejected = db.prepare("SELECT COUNT(*) as c FROM applications WHERE status='rejected'").get().c;
  const byCounty = db.prepare('SELECT county, COUNT(*) as count FROM applications GROUP BY county ORDER BY count DESC').all();
  res.json({ total, pending, approved, rejected, by_county: byCounty });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Start
app.listen(PORT, () => {
  console.log(`🎉 Utamu Agency Backend running on port ${PORT}`);
  console.log(`📁 Uploads directory: ${UPLOAD_DIR}`);
  console.log(`💾 Database: ${DB_PATH}`);
});
