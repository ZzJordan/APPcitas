const express = require('express');
const bcrypt = require('bcrypt');
const { db } = require('../db');
const { loginValidator, registerValidator } = require('../middleware/validators/authValidator');
const { handleValidationErrors } = require('../middleware/validators/handleValidation');
const rateLimit = require('express-rate-limit');
const path = require('path');

const router = express.Router();

// Rate Limiting para login
const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 5,
  message: 'Demasiados intentos de login, intenta más tarde',
  standardHeaders: true,
  legacyHeaders: false,
});

// Rutas públicas
router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'login.html'));
});

router.post('/login',
  loginLimiter,
  loginValidator,
  handleValidationErrors,
  (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM cupidos WHERE username = ?", [username], async (err, user) => {
      if (err) return res.status(500).json({ error: "Error en el servidor" });
      if (!user) return res.status(401).json({ error: "Usuario o contraseña incorrectos" });

      const match = await bcrypt.compare(password, user.password);
      if (match) {
        req.session.userId = user.id;
        req.session.username = user.username;
        res.status(200).json({ message: "Login exitoso" });
      } else {
        res.status(401).json({ error: "Usuario o contraseña incorrectos" });
      }
    });
  }
);

router.post('/logout', (req, res) => {
  req.session.destroy();
  res.status(200).json({ message: "Sesión cerrada" });
});

router.post('/register',
  registerValidator,
  handleValidationErrors,
  async (req, res) => {
    const { username, password } = req.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run("INSERT INTO cupidos (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) return res.status(400).json({ error: "El usuario ya existe" });
          return res.status(500).json({ error: "Error al registrar" });
        }
        req.session.userId = this.lastID;
        req.session.username = username;
        res.status(201).json({ message: "Registro exitoso" });
      });
    } catch (err) {
      res.status(500).json({ error: "Error en el servidor" });
    }
  }
);

module.exports = router;
