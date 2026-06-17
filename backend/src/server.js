const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware-uri de securitate
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true
}));

// Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting global
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minute
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Prea multe cereri de la această adresă IP, te rugăm să încerci mai târziu.',
  standardHeaders: true,
  legacyHeaders: false
});

app.use(limiter);

// Rate limiting special pentru autentificare
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: { success: false, message: 'Prea multe încercări de autentificare, te rugăm să aștepți 15 minute.' }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

// API routes
const authRoutes = require('./routes/authRoutes');
const mfaRoutes = require('./routes/mfaRoutes');

app.use(`/api/${process.env.API_VERSION || 'v1'}/auth`, authLimiter, authRoutes);
app.use(`/api/${process.env.API_VERSION || 'v1'}/mfa`, mfaRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Eroare:', err.stack);
  
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Eroare internă a serverului',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Ruta nu a fost găsită'
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║       🔐 SERVER MFA AUTENTIFICARE PORNIT! 🔐         ║
║                                                       ║
║   Port: ${PORT}                                      ║
║   Environment: ${process.env.NODE_ENV || 'development'}                            ║
║   API Version: ${process.env.API_VERSION || 'v1'}                                 ║
║                                                       ║
║   Health check: http://localhost:${PORT}/health       ║
║   API Base: http://localhost:${PORT}/api/${process.env.API_VERSION || 'v1'}         ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal primit. Se închide serverul...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT signal primit. Se închide serverul...');
  process.exit(0);
});

module.exports = app;
