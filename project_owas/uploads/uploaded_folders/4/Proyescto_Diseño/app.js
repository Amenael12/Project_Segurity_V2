const express = require('express');
const mysql = require('mysql');

const app = express();
app.use(express.urlencoded({ extended: true }));

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'vulnerableapp'
});

const usersRouter = require('./routes/users');
const loginRouter = require('./routes/login');
const filteredUsersRouter = require('./routes/filteredUsers');

app.use('/users', usersRouter(connection));
app.use('/login', loginRouter(connection));
app.use('/filtered-users', filteredUsersRouter(connection));

app.listen(3000, () => {
  console.log('Aplicación iniciada en http://localhost:3000');
});