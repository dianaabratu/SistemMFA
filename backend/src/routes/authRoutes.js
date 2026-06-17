const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');

const registerValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Email invalid'),
  body('username')
    .isLength({ min: 3, max: 50 }).trim()
    .withMessage('Username trebuie să aibă între 3 și 50 caractere'),
  body('password')
    .isLength({ min: 8 }).withMessage('Parola trebuie să aibă minimum 8 caractere')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]/)
    .withMessage('Parola trebuie să conțină cel puțin o literă mică, o literă mare, o cifră și un caracter special'),
  body('phoneNumber').optional().isMobilePhone().withMessage('Număr de telefon invalid')
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Email invalid'),
  body('password').notEmpty().withMessage('Parola este obligatorie')
];

const totpValidation = [
  body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Cod TOTP invalid (6 cifre)')
];

// Rute publice
router.post('/register', registerValidation, authController.register);
router.post('/login', loginValidation, authController.login);
router.post('/refresh-token', authController.refreshToken);

// Google OIDC
router.get('/google', authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

// Al doilea factor MFA — necesită tempToken în header Authorization
router.post('/mfa/totp/verify', totpValidation, authController.verifyTOTP);
router.post('/mfa/backup-code/verify', authController.verifyBackupCode);
router.get('/mfa/fido2/options', authController.getFido2AuthOptions);
router.post('/mfa/fido2/verify', authController.verifyFido2);

// Rute protejate (necesită JWT complet)
router.post('/logout', authenticateToken, authController.logout);
router.get('/profile', authenticateToken, authController.getProfile);
router.get('/audit-logs', authenticateToken, authController.getAuditLogs);

module.exports = router;
