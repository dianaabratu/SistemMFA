const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware pentru verificare token JWT
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Token de autentificare lipsă'
      });
    }

    // Verificare token
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({
            success: false,
            message: 'Token expirat'
          });
        }
        return res.status(403).json({
          success: false,
          message: 'Token invalid'
        });
      }

      // Verificare existență utilizator
      const user = await User.findById(decoded.userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'Utilizatorul nu există'
        });
      }

      if (!user.is_active) {
        return res.status(403).json({
          success: false,
          message: 'Contul este dezactivat'
        });
      }

      // Adăugare informații utilizator în request
      req.user = {
        id: user.id,
        email: user.email,
        username: user.username,
        mfaEnabled: user.mfa_enabled
      };

      next();
    });
  } catch (error) {
    console.error('Eroare la autentificare:', error);
    return res.status(500).json({
      success: false,
      message: 'Eroare la autentificare'
    });
  }
};

// Middleware pentru verificare MFA completă
const requireMFA = (req, res, next) => {
  if (req.user.mfaEnabled && !req.session?.mfaVerified) {
    return res.status(403).json({
      success: false,
      message: 'Verificare MFA necesară',
      requireMFA: true
    });
  }
  next();
};

module.exports = {
  authenticateToken,
  requireMFA
};
