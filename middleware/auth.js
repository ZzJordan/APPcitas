// Middleware de autenticación y autorización
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.status(401).json({ error: 'No autenticado' });
};

module.exports = { isAuthenticated };
