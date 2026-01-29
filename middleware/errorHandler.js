// Middleware de manejo de errores centralizado
const handleError = (err, req, res, next) => {
  const status = err.status || err.statusCode || 500;
  const message = err.message || 'Error interno del servidor';

  console.error(`[${new Date().toISOString()}] Error ${status}: ${message}`);

  // No revelar detalles de errores internos en producción
  if (process.env.NODE_ENV === 'production' && status === 500) {
    return res.status(status).json({ error: 'Error interno del servidor' });
  }

  res.status(status).json({ error: message });
};

// Middleware para manejo de rutas no encontradas
const notFoundHandler = (req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
};

module.exports = { handleError, notFoundHandler };
