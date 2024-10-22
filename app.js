const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const sqlite3 = require('sqlite3').verbose();
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const path = require('path');
const cors = require('cors');
const util = require('util');

// Load Swagger document
const swaggerDocument = YAML.load(path.join(__dirname, 'swagger.yaml'));

const app = express();
const port = process.env.PORT || 3001;

app.use(bodyParser.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/finance_tracker';
const DB_TYPE = process.env.DB_TYPE || 'mongodb'; // 'mongodb' or 'sqlite'

let db;

// Database abstraction layer
const dbLayer = {
  async connect() {
    if (DB_TYPE === 'mongodb') {
      const client = await MongoClient.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
      db = client.db();
      console.log('Connected to MongoDB');
    } else {
      db = new sqlite3.Database('./finance.db', (err) => {
        if (err) {
          console.error('Error opening database', err);
        } else {
          console.log('Connected to SQLite database');
          this.initializeSQLite();
        }
      });
    }
  },

  async initializeSQLite() {
    const run = util.promisify(db.run.bind(db));
    await run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )`);
    await run(`CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      type TEXT,
      category TEXT,
      amount REAL,
      date TEXT,
      description TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    await run(`CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      type TEXT
    )`);
  },

  async findOne(collection, query) {
    if (DB_TYPE === 'mongodb') {
      return await db.collection(collection).findOne(query);
    } else {
      const get = util.promisify(db.get.bind(db));
      const keys = Object.keys(query);
      const values = Object.values(query);
      const sqlQuery = `SELECT * FROM ${collection} WHERE ${keys.map(k => `${k} = ?`).join(' AND ')}`;
      return await get(sqlQuery, values);
    }
  },

  async insertOne(collection, document) {
    if (DB_TYPE === 'mongodb') {
      const result = await db.collection(collection).insertOne(document);
      return { insertedId: result.insertedId };
    } else {
      const run = util.promisify(db.run.bind(db));
      const keys = Object.keys(document);
      const values = Object.values(document);
      const sqlQuery = `INSERT INTO ${collection} (${keys.join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`;
      const result = await run(sqlQuery, values);
      return { insertedId: result.lastID };
    }
  },

  async find(collection, query, options = {}) {
    if (DB_TYPE === 'mongodb') {
      return await db.collection(collection).find(query, options).toArray();
    } else {
      const all = util.promisify(db.all.bind(db));
      const keys = Object.keys(query);
      const values = Object.values(query);
      let sqlQuery = `SELECT * FROM ${collection}`;
      if (keys.length > 0) {
        sqlQuery += ` WHERE ${keys.map(k => `${k} = ?`).join(' AND ')}`;
      }
      if (options.sort) {
        const sortField = Object.keys(options.sort)[0];
        const sortOrder = options.sort[sortField] === 1 ? 'ASC' : 'DESC';
        sqlQuery += ` ORDER BY ${sortField} ${sortOrder}`;
      }
      if (options.skip) sqlQuery += ` OFFSET ${options.skip}`;
      if (options.limit) sqlQuery += ` LIMIT ${options.limit}`;
      return await all(sqlQuery, values);
    }
  },

  async updateOne(collection, query, update) {
    if (DB_TYPE === 'mongodb') {
      return await db.collection(collection).updateOne(query, { $set: update });
    } else {
      const run = util.promisify(db.run.bind(db));
      const setKeys = Object.keys(update);
      const setValues = Object.values(update);
      const whereKeys = Object.keys(query);
      const whereValues = Object.values(query);
      const sqlQuery = `UPDATE ${collection} SET ${setKeys.map(k => `${k} = ?`).join(', ')} WHERE ${whereKeys.map(k => `${k} = ?`).join(' AND ')}`;
      const result = await run(sqlQuery, [...setValues, ...whereValues]);
      return { modifiedCount: result.changes };
    }
  },

  async deleteOne(collection, query) {
    if (DB_TYPE === 'mongodb') {
      return await db.collection(collection).deleteOne(query);
    } else {
      const run = util.promisify(db.run.bind(db));
      const keys = Object.keys(query);
      const values = Object.values(query);
      const sqlQuery = `DELETE FROM ${collection} WHERE ${keys.map(k => `${k} = ?`).join(' AND ')}`;
      const result = await run(sqlQuery, values);
      return { deletedCount: result.changes };
    }
  },

  async aggregate(collection, pipeline) {
    if (DB_TYPE === 'mongodb') {
      return await db.collection(collection).aggregate(pipeline).toArray();
    } else {
      // Implement SQLite aggregation based on the specific pipeline
      // This is a simplified version and may need to be adapted for complex aggregations
      const all = util.promisify(db.all.bind(db));
      const matchStage = pipeline.find(stage => stage.$match);
      const groupStage = pipeline.find(stage => stage.$group);
      
      let sqlQuery = `SELECT ${Object.keys(groupStage.$group).map(k => k === '_id' ? groupStage.$group[k] : `${groupStage.$group[k].$sum} as ${k}`).join(', ')}
                      FROM ${collection}`;
      
      if (matchStage) {
        const whereClause = Object.entries(matchStage.$match)
          .map(([key, value]) => `${key} = ?`)
          .join(' AND ');
        sqlQuery += ` WHERE ${whereClause}`;
      }
      
      sqlQuery += ` GROUP BY ${Object.values(groupStage.$group._id).join(', ')}`;
      
      const values = matchStage ? Object.values(matchStage.$match) : [];
      return await all(sqlQuery, values);
    }
  }
};

// Connect to the database
dbLayer.connect().catch(console.error);

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
  dbLayer.findOne('categories', { name: category, type: type }, (err, row) => {
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

// Add this route before any middleware
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the Personal Finance Tracker API' });
});

// Add the test route here as well
app.get('/test', (req, res) => {
  res.json({ message: 'Server is running' });
});

// Login and Register routes (these should not require authentication)
app.post('/login', (req, res) => {
  console.log('Login route hit');
  const { username, password } = req.body;

  dbLayer.findOne('users', { username: username }, (err, user) => {
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

app.post('/register', async (req, res) => {
  console.log('Register route hit');
  console.log('Request body:', req.body);
  const { username, password } = req.body;

  if (!username || !password) {
    console.log('Missing username or password');
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const existingUser = await dbLayer.findOne('users', { username: username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const result = await dbLayer.insertOne('users', { username: username, password: password });
    res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
  } catch (error) {
    console.error('Error in register route:', error);
    res.status(500).json({ error: 'Error creating user' });
  }
});

// Swagger UI route (should not require authentication)
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Apply authentication middleware only to routes that need it
app.use('/transactions', authenticateJWT);
app.use('/categories', authenticateJWT);
app.use('/summary', authenticateJWT);
app.use('/reports', authenticateJWT);

// Protected routes
app.post('/transactions', validateTransaction, (req, res) => {
  const { type, category, amount, date, description } = req.body;
  const userId = req.user.id;

  dbLayer.insertOne('transactions', {
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

  dbLayer.find('transactions', { user_id: userId }, { sort: { date: -1 }, skip: offset * limit, limit: limit }, (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/transactions/:id', (req, res) => {
  const userId = req.user.id;
  dbLayer.findOne('transactions', { id: ObjectId(req.params.id), user_id: userId }, (err, row) => {
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

  dbLayer.updateOne('transactions', {
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
  dbLayer.deleteOne('transactions', { id: ObjectId(req.params.id), user_id: userId }, (err, result) => {
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

  let matchStage = { user_id: userId };
  if (startDate) matchStage.date = { $gte: startDate };
  if (endDate) matchStage.date = { ...matchStage.date, $lte: endDate };
  if (category) matchStage.category = category;

  dbLayer.aggregate('transactions', [
    { $match: matchStage },
    { $group: { 
      _id: { type: '$type', category: '$category' }, 
      total: { $sum: '$amount' } 
    }}
  ]).then(rows => {
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
  }).catch(err => {
    console.error('Error in summary route:', err);
    res.status(500).json({ error: 'Error calculating summary' });
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

  dbLayer.find('transactions', { user_id: userId, type: 'expense', date: { $gte: startDate, $lte: endDate } }, { sort: { category: 1 } }, (err, rows) => {
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

  dbLayer.insertOne('categories', { name: name, type: type }, (err, result) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.status(201).json({ id: result.insertedId, name: name, type: type });
  });
});

app.get('/categories', authenticateJWT, (req, res) => {
  dbLayer.find('categories', {}, { sort: { name: 1 } }, (err, rows) => {
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