# Personal Finance API

This is a RESTful API for managing personal financial records. Users can record their income and expenses, retrieve past transactions, and get summaries by category or time period.

## New Features

- User authentication using JWT tokens
- Transactions are now linked to specific users
- Pagination for the GET /transactions endpoint
- New endpoint for generating monthly spending reports by category

## Setup and Run Instructions

1. Clone the repository:   ```
   git clone https://github.com/jay-chand-ra/PersonalExpenseTracker.git
   cd PersonalExpenseTracker   ```

2. Install dependencies:   ```
   npm install   ```

3. Start the server:   ```
   npm start   ```

The server will start running on `http://localhost:3000`.

## Authentication

This API now uses JWT for authentication. To get a token, use the /login endpoint:

- **URL:** `/login`
- **Method:** `POST`
- **Body:**  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }  ```
- **Success Response:** `200 OK`  ```json
  {
    "token": "your_jwt_token"
  }  ```

Include this token in the Authorization header for all other requests:

```
Authorization: Bearer your_jwt_token
