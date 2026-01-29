// Validadores para endpoints de salas
const { body, param } = require('express-validator');

const createRoomValidator = [
  body('friendA_name')
    .trim()
    .notEmpty().withMessage('Nombre de amigo A requerido')
    .isLength({ min: 2, max: 100 }).withMessage('Nombre debe tener entre 2 y 100 caracteres'),
  body('friendB_name')
    .trim()
    .notEmpty().withMessage('Nombre de amigo B requerido')
    .isLength({ min: 2, max: 100 }).withMessage('Nombre debe tener entre 2 y 100 caracteres'),
  body('noteA')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Nota A no puede exceder 500 caracteres'),
  body('noteB')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Nota B no puede exceder 500 caracteres')
];

const roomIdValidator = [
  param('id')
    .isInt({ min: 1 }).withMessage('ID de sala inválido')
];

const requestNewLinkValidator = [
  body('oldLink')
    .trim()
    .notEmpty().withMessage('Link antiguo requerido')
    .isUUID().withMessage('Link inválido')
];

module.exports = { createRoomValidator, roomIdValidator, requestNewLinkValidator };
