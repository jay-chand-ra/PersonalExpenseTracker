const axios = require('axios');
const { faker } = require('@faker-js/faker');

const BASE_URL = 'http://localhost:3001';

// Helper function to make authenticated requests
const authenticatedRequest = async (method, url, data, token) => {
  try {
    const response = await axios({
      method,
      url: `${BASE_URL}${url}`,
      data,
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  } catch (error) {
    console.error(`Error in ${method} ${url}:`, error.response ? error.response.data : error.message);
    throw error;
  }
};

// Create users
const createUsers = async (count) => {
  const users = [];
  for (let i = 0; i < count; i++) {
    const username = faker.internet.userName();
    const password = faker.internet.password();
    try {
      await axios.post(`${BASE_URL}/register`, { username, password });
      const loginResponse = await axios.post(`${BASE_URL}/login`, { username, password });
      users.push({ username, password, token: loginResponse.data.token });
      console.log(`Created user: ${username}`);
    } catch (error) {
      console.error(`Error creating user ${username}:`, error.response ? error.response.data : error.message);
    }
  }
  return users;
};

// Create categories
const createCategories = async (token) => {
  const categories = [
    { name: 'Groceries', type: 'expense' },
    { name: 'Rent', type: 'expense' },
    { name: 'Utilities', type: 'expense' },
    { name: 'Entertainment', type: 'expense' },
    { name: 'Salary', type: 'income' },
    { name: 'Freelance', type: 'income' },
    { name: 'Investments', type: 'income' }
  ];

  for (const category of categories) {
    try {
      await authenticatedRequest('post', '/categories', category, token);
      console.log(`Created category: ${category.name}`);
    } catch (error) {
      console.error(`Error creating category ${category.name}:`, error.response ? error.response.data : error.message);
    }
  }
};

// Create transactions
const createTransactions = async (user, count) => {
  const categories = await authenticatedRequest('get', '/categories', null, user.token);
  
  for (let i = 0; i < count; i++) {
    const category = faker.helpers.arrayElement(categories);
    const transaction = {
      type: category.type,
      category: category.name,
      amount: parseFloat(faker.finance.amount()),
      date: faker.date.past().toISOString().split('T')[0],
      description: faker.lorem.sentence()
    };

    try {
      await authenticatedRequest('post', '/transactions', transaction, user.token);
      console.log(`Created transaction for user ${user.username}: ${transaction.category} - ${transaction.amount}`);
    } catch (error) {
      console.error(`Error creating transaction for user ${user.username}:`, error.response ? error.response.data : error.message);
    }
  }
};

// Main function to populate the database
const populateDatabase = async () => {
  try {
    const users = await createUsers(5);
    await createCategories(users[0].token);
    for (const user of users) {
      await createTransactions(user, 20);
    }
    console.log('Database population completed successfully!');
  } catch (error) {
    console.error('Error populating database:', error);
  }
};

populateDatabase();
