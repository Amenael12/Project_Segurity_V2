const express = require('express');
const router = express.Router();

module.exports = (connection) => {
  // Vulnerabilidad 3: Inyección SQL en la consulta de usuarios con filtro
  router.get('/', (req, res) => {
    const filterValue = req.query.filter || '';
    const query = `SELECT * FROM users HAVING id ${filterValue}`;

    connection.query(query, (err, results) => {
      if (err) throw err;
      res.send(`<h1>Usuarios filtrados:</h1>${results.map(user => `<p>${user.name}</p>`).join('')}`);
    });
  });

  return router;
};