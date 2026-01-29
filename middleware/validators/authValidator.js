// Validadores para endpoints de autenticación
const { body } = require('express-validator');

const loginValidator = [
  body('username')
    .trim()
    .notEmpty().withMessage('Usuario requerido')
    .isLength({ min: 3 }).withMessage('Usuario muy corto'),
  body('password')
    .notEmpty().withMessage('Contraseña requerida')
    .isLength({ min: 6 }).withMessage('Contraseña muy corta')
];

const registerValidator = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 }).withMessage('Usuario debe tener entre 3 y 30 caracteres')
    .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Usuario solo puede contener letras, números, guiones y guiones bajos'),
  body('password')
    .isLength({ min: 6 }).withMessage('Contraseña debe tener al menos 6 caracteres')
    .isLength({ max: 128 }).withMessage('Contraseña muy larga'),
  body('confirmPassword')
    .custom((value, { req }) => value === req.body.password)
    .withMessage('Las contraseñas no coinciden')
];

module.exports = { loginValidator, registerValidator };
