const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const path = require('path');
const cors = require('cors');
const util = require('util');

const app = express();
const port = process.env.PORT || 3001;

// Load Swagger document
const swaggerDocument = YAML.load(path.join(__dirname, 'swagger.yaml'));

app.use(bodyParser.json());

// Use this CORS configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Setup Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key-why-do-you-want';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://jaychandra:1905145073@cluster0.xmyh7.mongodb.net/';

let db;

MongoClient.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    console.log('Connected to MongoDB');
    db = client.db('finance_tracker');
  })
  .catch(error => {
    console.error('MongoDB connection error:', util.inspect(error, { depth: null }));
    // You might want to send a response here if the database connection fails
    // res.status(500).json({ error: 'Database connection failed' });
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
  db.collection('categories').findOne({ name: category, type: type }, (err, row) => {
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
  res.json({ message: 'Server is running' });
});

// Login route
app.post('/login', (req, res) => {
  console.log('Login route hit');
  const { username, password } = req.body;

  db.collection('users').findOne({ username: username }, (err, user) => {
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
  console.log('Request body:', req.body);
  const { username, password } = req.body;

  if (!username || !password) {
    console.log('Missing username or password');
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.collection('users').findOne({ username: username }, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (user) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    db.collection('users').insertOne({ username: username, password: password }, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error creating user' });
      }

      res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
    });
  });
});

// Protected routes
app.use(authenticateJWT);

// Transactions routes
app.post('/transactions', validateTransaction, (req, res) => {
  const { type, category, amount, date, description } = req.body;
  const userId = req.user.id;

  db.collection('transactions').insertOne({
    user_id: userId,
    type: type,
    category: category,
    amount: amount,
    date: date,
    description: description
  }, (err, result) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.status(201).json({ id: result.insertedId });
  });
});

app.get('/transactions', (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;
  const userId = req.user.id;

  db.collection('transactions').find({ user_id: userId }).sort({ date: -1 }).skip(offset * limit).limit(limit).toArray((err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/transactions/:id', (req, res) => {
  const userId = req.user.id;
  db.collection('transactions').findOne({ id: ObjectId(req.params.id), user_id: userId }, (err, row) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json(row);
  });
});

app.put('/transactions/:id', validateTransaction, (req, res) => {
  const { type, category, amount, date, description } = req.body;
  const userId = req.user.id;

  db.collection('transactions').updateOne({
    id: ObjectId(req.params.id),
    user_id: userId
  }, {
    $set: {
      type: type,
      category: category,
      amount: amount,
      date: date,
      description: description
    }
  }, (err, result) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json({ message: 'Transaction updated successfully' });
  });
});

app.delete('/transactions/:id', (req, res) => {
  const userId = req.user.id;
  db.collection('transactions').deleteOne({ id: ObjectId(req.params.id), user_id: userId }, (err, result) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json({ message: 'Transaction deleted successfully' });
  });
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

  db.collection('transactions').aggregate([
    { $match: { user_id: userId } },
    { $match: { date: { $gte: startDate, $lte: endDate } } },
    { $match: { category: category } },
    { $group: { _id: { type: '$type', category: '$category' }, total: { $sum: '$amount' } } }
  ]).toArray((err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    const summary = {
      income: { total: 0, categories: {} },
      expenses: { total: 0, categories: {} },
      balance: 0
    };
    rows.forEach(row => {
      if (row._id.type === 'income') {
        summary.income.total += row.total;
        summary.income.categories[row._id.category] = row.total;
      } else if (row._id.type === 'expense') {
        summary.expenses.total += row.total;
        summary.expenses.categories[row._id.category] = row.total;
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

  db.collection('transactions').aggregate([
    { $match: { user_id: userId, type: 'expense', date: { $gte: startDate, $lte: endDate } } },
    { $group: { _id: '$category', total: { $sum: '$amount' } } }
  ]).toArray((err, rows) => {
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

  db.collection('categories').insertOne({ name: name, type: type }, (err, result) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.status(201).json({ id: result.insertedId, name: name, type: type });
  });
});

app.get('/categories', authenticateJWT, (req, res) => {
  db.collection('categories').find().toArray((err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Improve error handling
app.use((err, req, res, next) => {
  console.error('Error:', util.inspect(err, { depth: null }));
  res.status(500).json({ error: 'Something went wrong!', details: err.message });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
