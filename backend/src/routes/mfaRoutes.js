const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const mfaController = require('../controllers/mfaController');
const { authenticateToken } = require('../middleware/auth');

router.use(authenticateToken);

const confirmTOTPValidation = [
  body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Cod TOTP invalid (6 cifre)')
];

const disableMFAValidation = [
  body('password').notEmpty().withMessage('Parola este obligatorie pentru dezactivarea MFA')
];

const setPrimaryValidation = [
  body('methodType').isIn(['totp', 'fido2']).withMessage('Tip de metodă invalid')
];

// Metode configurate
router.get('/methods', mfaController.getMethods);

// TOTP (Google Authenticator / Authy)
router.post('/setup/totp', mfaController.setupTOTP);
router.post('/setup/totp/confirm', confirmTOTPValidation, mfaController.confirmTOTP);

// FIDO2 / WebAuthn
router.get('/setup/fido2/options', mfaController.getFido2RegistrationOptions);
router.post('/setup/fido2/complete', mfaController.completeFido2Registration);

// Gestionare metode
router.delete('/methods/:methodType', mfaController.deleteMethod);
router.post('/primary', setPrimaryValidation, mfaController.setPrimaryMethod);

// Activare / dezactivare MFA la nivel de cont
router.post('/enable', mfaController.enableMFA);
router.post('/disable', disableMFAValidation, mfaController.disableMFA);

// Coduri de backup (recuperare de urgență)
router.post('/backup-codes/:methodType', mfaController.generateBackupCodes);

module.exports = router;
