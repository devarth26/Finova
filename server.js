// server.js - Main server file
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 hour
}));

// Database setup
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to the SQLite database');
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        console.error('Error creating table', err.message);
      } else {
        console.log('Users table ready');
      }
    });
  }
});

// Routes
app.post('/api/signup', (req, res) => {
  const { username, email, password } = req.body;
  
  // Input validation
  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }
  
  // Check if user already exists
  db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], async (err, user) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    if (user) {
      return res.status(409).json({ success: false, message: 'User already exists' });
    }
    
    try {
      // Hash password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      // Store user in database
      const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
      stmt.run(username, email, hashedPassword, function(err) {
        if (err) {
          return res.status(500).json({ success: false, message: 'Error creating user' });
        }
        res.status(201).json({ success: true, message: 'User registered successfully', userId: this.lastID });
      });
      stmt.finalize();
    } catch (error) {
      res.status(500).json({ success: false, message: 'Server error' });
    }
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  // Input validation
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }
  
  // Check if user exists
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    try {
      // Compare password
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }
      
      // Set session
      req.session.userId = user.id;
      req.session.username = user.username;
      
      res.status(200).json({ success: true, message: 'Login successful', username: user.username });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Server error' });
    }
  });
});

// Check authentication status
app.get('/api/check-auth', (req, res) => {
  if (req.session.userId) {
    return res.status(200).json({ 
      authenticated: true, 
      username: req.session.username 
    });
  }
  res.status(200).json({ authenticated: false });
});

// Logout route
app.get('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Logout failed' });
    }
    res.status(200).json({ success: true, message: 'Logged out successfully' });
  });
});

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Protected route example
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});