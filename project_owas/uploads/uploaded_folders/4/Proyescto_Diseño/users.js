const express = require('express');
const router = express.Router();

module.exports = (connection) => {
  // Vulnerabilidad 1: Inyección SQL en la búsqueda de usuarios
  router.get('/', (req, res) => {
    const searchTerm = req.query.search || '';
    const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;

    connection.query(query, (err, results) => {
      if (err) throw err;
      res.send(`<h1>Resultados de búsqueda:</h1>${results.map(user => `<p>${user.name}</p>`).join('')}`);
    });
  });

  return router;
};