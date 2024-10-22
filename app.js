const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
// const basicAuth = require('express-basic-auth');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./swagger.yaml');

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(bodyParser.json());

// JWT Secret
const JWT_SECRET = 'your-secret-key'; // In production, use an environment variable

// Database setup
const db = new sqlite3.Database('./finance.db', (err) => {
  if (err) {
    console.error('Error opening database', err);
  } else {
    console.log('Connected to the SQLite database.');
    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
      )`);
      db.run(`CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT CHECK(type IN ('income', 'expense')),
        category TEXT,
        amount REAL,
        date TEXT,
        description TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`);
      
      // Check if user_id column exists and add it if it doesn't
      db.all(`PRAGMA table_info(transactions)`, (err, rows) => {
        if (err) {
          console.error('Error checking table info:', err);
        } else {
          const userIdColumnExists = rows.some(row => row.name === 'user_id');
          if (!userIdColumnExists) {
            db.run(`ALTER TABLE transactions ADD COLUMN user_id INTEGER REFERENCES users(id)`, (err) => {
              if (err) {
                console.error('Error adding user_id column:', err);
              } else {
                console.log('Added user_id column to transactions table');
              }
            });
          }
        }
      });

      // Add categories table
      db.run(`CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        type TEXT CHECK(type IN ('income', 'expense'))
      )`);
    });
  }
});

// Input validation middleware
const validateTransaction = (req, res, next) => {
  const { type, category, amount, date } = req.body;
  if (!type || !category || !amount || !date) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (type !== 'income' && type !== 'expense') {
    return res.status(400).json({ error: 'Invalid transaction type' });
  }
  if (typeof amount !== 'number' || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  if (isNaN(Date.parse(date))) {
    return res.status(400).json({ error: 'Invalid date format' });
  }

  // Check if the category exists and matches the transaction type
  db.get('SELECT * FROM categories WHERE name = ? AND type = ?', [category, type], (err, row) => {
    if (err || !row) {
      return res.status(400).json({ error: 'Invalid category for the transaction type' });
    }
    next();
  });
};

// Authentication middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Add this line before the authenticateJWT middleware
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Add this route before any middleware
app.get('/test', (req, res) => {
  res.json({ message: 'Test route is working' });
});

// Login route
app.post('/login', (req, res) => {
  console.log('Login route hit');
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  });
});

// Registration route
app.post('/register', (req, res) => {
  console.log('Register route hit');
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (user) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error creating user' });
      }

      res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
    });
  });
});

// Protected routes
app.use(authenticateJWT);

// Transactions routes
app.post('/transactions', validateTransaction, (req, res) => {
  const { type, category, amount, date, description } = req.body;
  const userId = req.user.id;

  db.run(
    'INSERT INTO transactions (user_id, type, category, amount, date, description) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, type, category, amount, date, description],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      res.status(201).json({ id: this.lastID });
    }
  );
});

app.get('/transactions', (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;
  const userId = req.user.id;

  db.all(
    'SELECT * FROM transactions WHERE user_id = ? LIMIT ? OFFSET ?',
    [userId, limit, offset],
    (err, rows) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      res.json(rows);
    }
  );
});

app.get('/transactions/:id', (req, res) => {
  const userId = req.user.id;
  db.get(
    'SELECT * FROM transactions WHERE id = ? AND user_id = ?',
    [req.params.id, userId],
    (err, row) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      if (!row) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      res.json(row);
    }
  );
});

app.put('/transactions/:id', validateTransaction, (req, res) => {
  const { type, category, amount, date, description } = req.body;
  const userId = req.user.id;

  db.run(
    'UPDATE transactions SET type = ?, category = ?, amount = ?, date = ?, description = ? WHERE id = ? AND user_id = ?',
    [type, category, amount, date, description, req.params.id, userId],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      res.json({ message: 'Transaction updated successfully' });
    }
  );
});

app.delete('/transactions/:id', (req, res) => {
  const userId = req.user.id;
  db.run(
    'DELETE FROM transactions WHERE id = ? AND user_id = ?',
    [req.params.id, userId],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Transaction not found' });
      }
      res.json({ message: 'Transaction deleted successfully' });
    }
  );
});

app.get('/summary', authenticateJWT, (req, res) => {
  const { startDate, endDate, category } = req.query;
  const userId = req.user.id;

  if ((startDate && isNaN(Date.parse(startDate))) || (endDate && isNaN(Date.parse(endDate)))) {
    return res.status(400).json({ error: 'Invalid date format' });
  }

  let query = 'SELECT type, category, SUM(amount) as total FROM transactions WHERE user_id = ?';
  const params = [userId];

  if (startDate) {
    query += ' AND date >= ?';
    params.push(startDate);
  }
  if (endDate) {
    query += ' AND date <= ?';
    params.push(endDate);
  }
  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }

  query += ' GROUP BY type, category';

  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    const summary = {
      income: { total: 0, categories: {} },
      expenses: { total: 0, categories: {} },
      balance: 0
    };
    rows.forEach(row => {
      if (row.type === 'income') {
        summary.income.total += row.total;
        summary.income.categories[row.category] = row.total;
      } else if (row.type === 'expense') {
        summary.expenses.total += row.total;
        summary.expenses.categories[row.category] = row.total;
      }
    });
    summary.balance = summary.income.total - summary.expenses.total;
    res.json(summary);
  });
});

// New endpoint for generating monthly spending by category report
app.get('/reports/monthly-spending', (req, res) => {
  const { year, month } = req.query;
  const userId = req.user.id;

  if (!year || !month) {
    return res.status(400).json({ error: 'Year and month are required' });
  }

  const startDate = `${year}-${month.padStart(2, '0')}-01`;
  const endDate = `${year}-${month.padStart(2, '0')}-31`;

  const query = `
    SELECT category, SUM(amount) as total
    FROM transactions
    WHERE user_id = ? AND type = 'expense' AND date BETWEEN ? AND ?
    GROUP BY category
    ORDER BY total DESC
  `;

  db.all(query, [userId, startDate, endDate], (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Categories routes
app.post('/categories', authenticateJWT, (req, res) => {
  const { name, type } = req.body;
  if (!name || !type || (type !== 'income' && type !== 'expense')) {
    return res.status(400).json({ error: 'Invalid category data' });
  }

  db.run('INSERT INTO categories (name, type) VALUES (?, ?)', [name, type], function(err) {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.status(201).json({ id: this.lastID, name, type });
  });
});

app.get('/categories', authenticateJWT, (req, res) => {
  db.all('SELECT * FROM categories', (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Improve error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
