const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const db = new Database('/opt/crm/crm.db');
const JWT_SECRET = 'crm_secret_2026_gezimm';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- DB SETUP ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    department TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    status TEXT DEFAULT 'aktiv',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    assigned_to INTEGER,
    priority TEXT DEFAULT 'normale',
    status TEXT DEFAULT 'në pritje',
    due_date TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assigned_to) REFERENCES employees(id)
  );
  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    check_in TEXT,
    check_out TEXT,
    hours_worked REAL,
    notes TEXT,
    FOREIGN KEY(employee_id) REFERENCES employees(id)
  );
`);

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@crm.com');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run('Administrator', 'admin@crm.com', hash, 'admin');
}

// --- AUTH MIDDLEWARE ---
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Pa autorizim' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token i pavlefshëm' }); }
}

// --- AUTH ROUTES ---
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Email ose fjalëkalim i gabuar' });
  const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// --- EMPLOYEES ---
app.get('/api/employees', auth, (req, res) => {
  const emps = db.prepare('SELECT * FROM employees ORDER BY name').all();
  res.json(emps);
});
app.post('/api/employees', auth, (req, res) => {
  const { name, role, department, email, phone } = req.body;
  const r = db.prepare('INSERT INTO employees (name, role, department, email, phone) VALUES (?,?,?,?,?)').run(name, role, department, email, phone);
  res.json({ id: r.lastInsertRowid, name, role, department, email, phone, status: 'aktiv' });
});
app.put('/api/employees/:id', auth, (req, res) => {
  const { name, role, department, email, phone, status } = req.body;
  db.prepare('UPDATE employees SET name=?, role=?, department=?, email=?, phone=?, status=? WHERE id=?').run(name, role, department, email, phone, status, req.params.id);
  res.json({ success: true });
});
app.delete('/api/employees/:id', auth, (req, res) => {
  db.prepare('DELETE FROM employees WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// --- TASKS ---
app.get('/api/tasks', auth, (req, res) => {
  const tasks = db.prepare(`
    SELECT t.*, e.name as employee_name FROM tasks t
    LEFT JOIN employees e ON t.assigned_to = e.id
    ORDER BY t.created_at DESC
  `).all();
  res.json(tasks);
});
app.post('/api/tasks', auth, (req, res) => {
  const { title, description, assigned_to, priority, status, due_date } = req.body;
  const r = db.prepare('INSERT INTO tasks (title, description, assigned_to, priority, status, due_date) VALUES (?,?,?,?,?,?)').run(title, description, assigned_to, priority, status || 'në pritje', due_date);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/tasks/:id', auth, (req, res) => {
  const { title, description, assigned_to, priority, status, due_date } = req.body;
  db.prepare('UPDATE tasks SET title=?, description=?, assigned_to=?, priority=?, status=?, due_date=? WHERE id=?').run(title, description, assigned_to, priority, status, due_date, req.params.id);
  res.json({ success: true });
});
app.delete('/api/tasks/:id', auth, (req, res) => {
  db.prepare('DELETE FROM tasks WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// --- ATTENDANCE ---
app.get('/api/attendance', auth, (req, res) => {
  const { month, employee_id } = req.query;
  let q = `SELECT a.*, e.name as employee_name FROM attendance a JOIN employees e ON a.employee_id = e.id WHERE 1=1`;
  const params = [];
  if (month) { q += ' AND a.date LIKE ?'; params.push(month + '%'); }
  if (employee_id) { q += ' AND a.employee_id = ?'; params.push(employee_id); }
  q += ' ORDER BY a.date DESC, e.name';
  res.json(db.prepare(q).all(...params));
});
app.post('/api/attendance', auth, (req, res) => {
  const { employee_id, date, check_in, check_out, notes } = req.body;
  let hours_worked = null;
  if (check_in && check_out) {
    const [h1, m1] = check_in.split(':').map(Number);
    const [h2, m2] = check_out.split(':').map(Number);
    hours_worked = ((h2 * 60 + m2) - (h1 * 60 + m1)) / 60;
  }
  const existing = db.prepare('SELECT id FROM attendance WHERE employee_id=? AND date=?').get(employee_id, date);
  if (existing) {
    db.prepare('UPDATE attendance SET check_in=?, check_out=?, hours_worked=?, notes=? WHERE id=?').run(check_in, check_out, hours_worked, notes, existing.id);
    res.json({ success: true, updated: true });
  } else {
    const r = db.prepare('INSERT INTO attendance (employee_id, date, check_in, check_out, hours_worked, notes) VALUES (?,?,?,?,?,?)').run(employee_id, date, check_in, check_out, hours_worked, notes);
    res.json({ id: r.lastInsertRowid });
  }
});
app.delete('/api/attendance/:id', auth, (req, res) => {
  db.prepare('DELETE FROM attendance WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// --- DASHBOARD ---
app.get('/api/dashboard', auth, (req, res) => {
  const total_employees = db.prepare("SELECT COUNT(*) as c FROM employees WHERE status='aktiv'").get().c;
  const total_tasks = db.prepare('SELECT COUNT(*) as c FROM tasks').get().c;
  const tasks_done = db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status='përfunduar'").get().c;
  const tasks_pending = db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status='në pritje'").get().c;
  const tasks_progress = db.prepare("SELECT COUNT(*) as c FROM tasks WHERE status='në progres'").get().c;
  const today = new Date().toISOString().split('T')[0];
  const present_today = db.prepare('SELECT COUNT(*) as c FROM attendance WHERE date=?').get(today).c;
  const month = today.slice(0, 7);
  const avg_hours = db.prepare('SELECT AVG(hours_worked) as a FROM attendance WHERE date LIKE ? AND hours_worked IS NOT NULL').get(month + '%').a;
  const by_dept = db.prepare("SELECT department, COUNT(*) as count FROM employees WHERE status='aktiv' GROUP BY department").all();
  const recent_tasks = db.prepare(`SELECT t.title, t.status, t.priority, e.name as employee_name FROM tasks t LEFT JOIN employees e ON t.assigned_to=e.id ORDER BY t.created_at DESC LIMIT 5`).all();
  res.json({ total_employees, total_tasks, tasks_done, tasks_pending, tasks_progress, present_today, avg_hours: avg_hours ? avg_hours.toFixed(1) : 0, by_dept, recent_tasks });
});

app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(3000, () => console.log('CRM running on port 3000'));
