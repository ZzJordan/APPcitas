// Validadores para endpoints de chat
const { body, param } = require('express-validator');

const sendMessageValidator = [
  param('link')
    .trim()
    .notEmpty().withMessage('Link requerido')
    .isUUID().withMessage('Link inválido'),
  body('text')
    .trim()
    .notEmpty().withMessage('Mensaje no puede estar vacío')
    .isLength({ min: 1, max: 1000 }).withMessage('Mensaje debe tener entre 1 y 1000 caracteres'),
  body('side')
    .isIn(['A', 'B']).withMessage('Side debe ser A o B')
];

const chatInfoValidator = [
  param('link')
    .trim()
    .notEmpty().withMessage('Link requerido')
    .isUUID().withMessage('Link inválido')
];

module.exports = { sendMessageValidator, chatInfoValidator };
