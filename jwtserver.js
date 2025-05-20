const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key_here_change_this_to_a_strong_secret'; // Change to a strong secret in production
const TOKEN_EXPIRATION = '2h';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite DB
const db = new sqlite3.Database('./messages.db', (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Create messages table if not exists
db.run(`CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`);

// Helper: Generate JWT
function generateToken(user) {
  const payload = {
    id: user.id,
    username: user.username
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
}

// Middleware: Authenticate JWT Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Malformed token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Failed to authenticate token' });
    req.user = user; // attach user info to request
    next();
  });
}

// Register new user
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.trim() === '' || password.trim() === '') {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Check if user exists
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (row) return res.status(409).json({ error: 'Username already exists' });

      // Hash password
      const password_hash = await bcrypt.hash(password, 10);

      // Insert new user
      const stmt = db.prepare('INSERT INTO users(username, password_hash) VALUES(?, ?)');
      stmt.run(username, password_hash, function(err2) {
        if (err2) return res.status(500).json({ error: 'Failed to register user' });

        // Return created user info (no password)
        const newUser = { id: this.lastID, username };
        const token = generateToken(newUser);
        return res.status(201).json({ user: newUser, token });
      });
      stmt.finalize();
    });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Login user
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.trim() === '' || password.trim() === '') {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.get('SELECT id, username, password_hash FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ user: { id: user.id, username: user.username }, token });
  });
});

// Get all messages (protected)
app.get('/api/messages', authenticateToken, (req, res) => {
  // Include username on each message by joining users table
  const sql = `
    SELECT m.id, m.content, m.created_at, u.username
    FROM messages m
    JOIN users u ON m.user_id = u.id
    ORDER BY m.created_at ASC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve messages' });
    }
    return res.json(rows);
  });
});

// Post a new message (protected)
app.post('/api/messages', authenticateToken, (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === '') {
    return res.status(400).json({ error: 'Message content is required' });
  }

  const userId = req.user.id;
  const stmt = db.prepare('INSERT INTO messages(user_id, content) VALUES(?, ?)');
  stmt.run(userId, content.trim(), function (err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to save message' });
    }
    // Return the new message including username and timestamp
    const sql = `
      SELECT m.id, m.content, m.created_at, u.username
      FROM messages m
      JOIN users u ON m.user_id = u.id
      WHERE m.id = ?
    `;
    db.get(sql, [this.lastID], (err2, row) => {
      if (err2) {
        return res.status(500).json({ error: 'Failed to retrieve new message' });
      }
      return res.status(201).json(row);
    });
  });
  stmt.finalize();
});

// Serve frontend fallback (if needed)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.listen(PORT, () => {
  console.log(\`Server running at http://localhost:\${PORT}\`);
});

