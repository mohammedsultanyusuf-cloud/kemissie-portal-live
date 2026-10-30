'use strict';
require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const rateLimit = require('express-rate-limit');

const {
    PORT = 3000,
    DB_HOST = 'localhost',
    DB_PORT = 3306,
    DB_USER = 'root',
    DB_PASSWORD = '',
    DB_NAME = 'kemissie_school',
    JWT_SECRET,
    ADMIN_PASSWORD,
    SEED_DEMO = 'true',
    CORS_ORIGIN = '*'
} = process.env;

if (!JWT_SECRET || !ADMIN_PASSWORD) {
    console.error('Missing JWT_SECRET or ADMIN_PASSWORD. Copy .env.example to .env and fill it in.');
    process.exit(1);
}

const pool = mysql.createPool({
    host: DB_HOST,
    port: Number(DB_PORT),
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    charset: 'utf8mb4'
});

/* ---------- constants & helpers ---------- */
const ALLOWED_SUBJECTS = new Set([
    'English', 'Mathematics', 'Physics', 'Chemistry', 'Biology', 'Geography', 'History',
    'Citizenship Education (Civics)', 'Economics', 'Information Technology (IT)',
    'Health and Physical Education (HPE)', 'Mother Tongue / Amharic', 'Agriculture'
]);
const ID_RE = /^[A-Z0-9]{3,20}$/;
const ADMIN_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10);

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clamp = (v, max) => Math.min(max, Math.max(0, parseInt(v, 10) || 0));
const sign = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });
const validSem = (s) => s === '1' || s === '2';

function requireRole(role) {
    return (req, res, next) => {
        const h = req.headers.authorization || '';
        const token = h.startsWith('Bearer ') ? h.slice(7) : '';
        try {
            const payload = jwt.verify(token, JWT_SECRET);
            if (payload.role !== role) throw new Error('wrong role');
            req.auth = payload;
            next();
        } catch (e) {
            res.status(401).json({ error: 'Unauthorized' });
        }
    };
}

async function tx(fn) {
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        const result = await fn(conn);
        await conn.commit();
        return result;
    } catch (e) {
        await conn.rollback();
        throw e;
    } finally {
        conn.release();
    }
}

async function gradesFor(db, sid) {
    const [rows] = await db.query(
        'SELECT semester, subject, midterm, final_exam FROM grades WHERE student_id = ? ORDER BY semester, id', [sid]);
    const out = { '1': [], '2': [] };
    rows.forEach(r => out[String(r.semester)].push({ subject: r.subject, midterm: r.midterm, final: r.final_exam }));
    return out;
}

async function replaceGrades(conn, sid, sem, list) {
    await conn.query('DELETE FROM grades WHERE student_id = ? AND semester = ?', [sid, sem]);
    const seen = new Set();
    const rows = [];
    for (const g of list) {
        if (!g || !ALLOWED_SUBJECTS.has(g.subject) || seen.has(g.subject)) continue;
        seen.add(g.subject);
        rows.push([sid, sem, g.subject, clamp(g.midterm, 40), clamp(g.final, 60)]);
    }
    if (rows.length) {
        await conn.query('INSERT INTO grades (student_id, semester, subject, midterm, final_exam) VALUES ?', [rows]);
    }
}

async function studentExists(sid) {
    const [rows] = await pool.query('SELECT 1 FROM students WHERE student_id = ?', [sid]);
    return rows.length > 0;
}

async function generateUniqueId() {
    for (;;) {
        const id = 'KEM' + crypto.randomInt(1000, 10000);
        if (!(await studentExists(id))) return id;
    }
}
const generatePassword = () => String(crypto.randomInt(100000, 1000000));

async function seedDemo() {
    const [[{ n }]] = await pool.query('SELECT COUNT(*) AS n FROM students');
    if (n > 0) return;
    await tx(async (conn) => {
        await conn.query('INSERT INTO students (student_id, name, password_hash) VALUES (?, ?, ?)',
            ['KEM123', 'Abebe Kebede', await bcrypt.hash('1234', 10)]);
        await replaceGrades(conn, 'KEM123', 1, [
            { subject: 'Mathematics', midterm: 32, final: 50 },
            { subject: 'English', midterm: 35, final: 55 }
        ]);
        await replaceGrades(conn, 'KEM123', 2, [{ subject: 'Mathematics', midterm: 30, final: 45 }]);
    });
    console.log('Demo student created: KEM123 / 1234 (set SEED_DEMO=false in production)');
}

/* ---------- app ---------- */
const app = express();
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()) }));
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.redirect('/project.html'));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts. Please try again later.' }
});

/* ---------- student ---------- */
app.post('/api/student/login', loginLimiter, wrap(async (req, res) => {
    const sid = String(req.body.studentId || '').toUpperCase().trim();
    const pass = String(req.body.password || '').trim();
    const [rows] = await pool.query('SELECT student_id, name, password_hash FROM students WHERE student_id = ?', [sid]);
    const s = rows[0];
    if (!s || !(await bcrypt.compare(pass, s.password_hash))) {
        return res.status(401).json({ error: 'Invalid ID or Password' });
    }
    res.json({
        token: sign({ role: 'student', sid: s.student_id }),
        student: { id: s.student_id, name: s.name },
        grades: await gradesFor(pool, s.student_id)
    });
}));

app.get('/api/student/grades', requireRole('student'), wrap(async (req, res) => {
    res.json({ grades: await gradesFor(pool, req.auth.sid) });
}));

/* ---------- admin ---------- */
app.post('/api/admin/login', loginLimiter, wrap(async (req, res) => {
    const pass = String(req.body.password || '');
    if (!(await bcrypt.compare(pass, ADMIN_HASH))) return res.status(401).json({ error: 'Invalid Admin Password' });
    res.json({ token: sign({ role: 'admin' }) });
}));

const admin = requireRole('admin');

app.get('/api/admin/generate-credentials', admin, wrap(async (req, res) => {
    res.json({ studentId: await generateUniqueId(), password: generatePassword() });
}));

app.get('/api/admin/students', admin, wrap(async (req, res) => {
    const [rows] = await pool.query(
        `SELECT s.student_id AS id, s.name, COUNT(g.id) AS gradeCount
           FROM students s LEFT JOIN grades g ON g.student_id = s.student_id
          GROUP BY s.student_id, s.name, s.created_at
          ORDER BY s.created_at, s.student_id`);
    res.json(rows);
}));

app.post('/api/admin/students', admin, wrap(async (req, res) => {
    const b = req.body || {};
    const sid = String(b.studentId || '').toUpperCase().trim();
    const first = String(b.firstName || '').trim();
    const last = String(b.lastName || '').trim();
    const pw = String(b.password || '');
    const name = (first + ' ' + last).trim();
    if (!ID_RE.test(sid) || !first || !last || name.length > 150 || pw.length < 4) {
        return res.status(400).json({ error: 'Invalid registration data' });
    }
    try {
        await pool.query('INSERT INTO students (student_id, name, password_hash) VALUES (?, ?, ?)',
            [sid, name, await bcrypt.hash(pw, 10)]);
    } catch (e) {
        if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'This ID already exists' });
        throw e;
    }
    res.status(201).json({ ok: true, id: sid });
}));

app.post('/api/admin/students/:id/reset-password', admin, wrap(async (req, res) => {
    const sid = String(req.params.id).toUpperCase().trim();
    const password = generatePassword();
    const [result] = await pool.query('UPDATE students SET password_hash = ? WHERE student_id = ?',
        [await bcrypt.hash(password, 10), sid]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Student not found' });
    res.json({ password });
}));

app.get('/api/admin/students/:id/grades/:sem', admin, wrap(async (req, res) => {
    const sid = String(req.params.id).toUpperCase().trim();
    if (!validSem(req.params.sem)) return res.status(400).json({ error: 'Invalid semester' });
    if (!(await studentExists(sid))) return res.status(404).json({ error: 'Student not found' });
    res.json({ grades: (await gradesFor(pool, sid))[req.params.sem] });
}));

app.put('/api/admin/students/:id/grades/:sem', admin, wrap(async (req, res) => {
    const sid = String(req.params.id).toUpperCase().trim();
    if (!validSem(req.params.sem)) return res.status(400).json({ error: 'Invalid semester' });
    if (!Array.isArray(req.body.grades)) return res.status(400).json({ error: 'grades must be an array' });
    if (!(await studentExists(sid))) return res.status(404).json({ error: 'Student not found' });
    await tx(conn => replaceGrades(conn, sid, Number(req.params.sem), req.body.grades));
    res.json({ ok: true });
}));

/* ---------- backup / restore ---------- */
app.get('/api/admin/backup', admin, wrap(async (req, res) => {
    const [studentRows] = await pool.query('SELECT student_id, name, password_hash FROM students ORDER BY created_at, student_id');
    const [gradeRows] = await pool.query('SELECT student_id, semester, subject, midterm, final_exam FROM grades ORDER BY id');
    const out = {};
    studentRows.forEach(s => {
        out[s.student_id] = { name: s.name, passwordHash: s.password_hash, grades: { '1': [], '2': [] } };
    });
    gradeRows.forEach(g => {
        if (out[g.student_id]) {
            out[g.student_id].grades[String(g.semester)].push({ subject: g.subject, midterm: g.midterm, final: g.final_exam });
        }
    });
    res.json(out);
}));

app.post('/api/admin/restore', admin, wrap(async (req, res) => {
    const data = req.body;
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
        return res.status(400).json({ error: 'Invalid backup format' });
    }
    let merged = 0;
    await tx(async (conn) => {
        for (const [rawId, s] of Object.entries(data)) {
            const sid = String(rawId).toUpperCase().trim();
            if (!ID_RE.test(sid) || !s || typeof s !== 'object') continue;
            let hash = null;
            if (typeof s.passwordHash === 'string' && /^\$2[aby]\$/.test(s.passwordHash)) hash = s.passwordHash;
            else if (s.password != null && String(s.password).length > 0) hash = await bcrypt.hash(String(s.password), 10);
            if (!hash) continue;
            await conn.query(
                `INSERT INTO students (student_id, name, password_hash) VALUES (?, ?, ?)
                 ON DUPLICATE KEY UPDATE name = VALUES(name), password_hash = VALUES(password_hash)`,
                [sid, String(s.name || 'N/A').slice(0, 150), hash]);
            for (const sem of ['1', '2']) {
                if (s.grades && Array.isArray(s.grades[sem])) await replaceGrades(conn, sid, Number(sem), s.grades[sem]);
            }
            merged++;
        }
    });
    res.json({ merged });
}));

/* ---------- errors ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {   // eslint-disable-line no-unused-vars
    const status = err.status || 500;
    if (status === 500) console.error(err);
    res.status(status).json({ error: status === 500 ? 'Server error' : err.message });
});

(async () => {
    try {
        await pool.query('SELECT 1');
        // ዳታቤዝ ሰንጠረዦች ከሌሉ አውቶማቲክ መፍጠሪያ
        await pool.query(`
            CREATE TABLE IF NOT EXISTS students (
                student_id VARCHAR(20) PRIMARY KEY,
                name VARCHAR(150) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS grades (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id VARCHAR(20) NOT NULL,
                semester TINYINT NOT NULL,
                subject VARCHAR(100) NOT NULL,
                midterm INT NOT NULL DEFAULT 0,
                final_exam INT NOT NULL DEFAULT 0,
                FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
            )
        `);

        if (SEED_DEMO === 'true') await seedDemo();
        app.listen(PORT, () => {
            console.log(`Kemissie School server running: http://localhost:${PORT}`);
            
            // 24 ሰዓት Active እንዲሆን በየ 14 ደቂቃው ራሱን የሚቀሰቅስ (Auto-Ping)
            if (process.env.RENDER_EXTERNAL_URL) {
                setInterval(() => {
                    fetch(process.env.RENDER_EXTERNAL_URL).catch(() => {});
                }, 14 * 60 * 1000);
            }
        });
    } catch (e) {
        console.error('Startup failed:', e.message);
        process.exit(1);
    }
})();