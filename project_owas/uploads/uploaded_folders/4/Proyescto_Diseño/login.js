const express = require('express');
const router = express.Router();

module.exports = (connection) => {
  // Vulnerabilidad 2: Inyección SQL en la autenticación
  router.post('/', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    connection.query(query, (err, results) => {
      if (err) throw err;
      if (results.length > 0) {
        res.send('Inicio de sesión exitoso');
      } else {
        res.send('Credenciales inválidas');
      }
    });
  });

  return router;
};