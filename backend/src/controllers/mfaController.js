const { validationResult } = require('express-validator');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const User = require('../models/User');
const MFA = require('../models/MFA');
const totpService = require('../services/totpService');
const auditLogger = require('../utils/auditLogger');
const challengeStore = require('../utils/challengeStore');
const db = require('../config/database');

const RP_ID = process.env.FIDO2_RP_ID || 'localhost';
const ORIGIN = process.env.FIDO2_ORIGIN || 'http://localhost:3000';

// Activează automat MFA pe cont dacă nu era deja activ
async function autoEnableMFA(userId, ipAddress, userAgent) {
  const user = await User.findById(userId);
  if (user.mfa_enabled) return;

  await User.toggleMFA(userId, true);

  const methods = await MFA.getUserMethods(userId);
  const active = methods.filter(m => m.is_enabled);
  if (active.length > 0 && !active.find(m => m.is_primary)) {
    await MFA.setPrimaryMethod(userId, active[0].method_type);
  }

  await auditLogger.log({
    userId,
    action: 'MFA_ENABLED',
    resource: 'mfa',
    status: 'success',
    ipAddress,
    userAgent,
    details: { trigger: 'auto' },
  });
}

class MFAController {
  // Obținere metode MFA configurate
  async getMethods(req, res) {
    try {
      const userId = req.user.id;
      const methods = await MFA.getUserMethods(userId);

      res.json({
        success: true,
        methods: methods.map(m => ({
          type: m.method_type,
          isPrimary: m.is_primary,
          isEnabled: m.is_enabled,
          phoneNumber: m.phone_number ? `***${m.phone_number.slice(-4)}` : null,
          createdAt: m.created_at
        }))
      });
    } catch (error) {
      console.error('Eroare la obținerea metodelor MFA:', error);
      res.status(500).json({ success: false, message: 'Eroare la obținerea metodelor MFA' });
    }
  }

  // ── TOTP ──────────────────────────────────────────────────────────────────

  // Inițiere setup TOTP — returnează secret + QR code
  async setupTOTP(req, res) {
    try {
      const userId = req.user.id;
      const user = await User.findById(userId);

      const secret = totpService.generateSecret(user.email);
      const qrCode = await totpService.generateQRCode(secret.otpauth_url);

      // Salvare secret (neactivat) în DB
      await totpService.savePendingSecret(userId, secret.base32);

      await auditLogger.log({
        userId,
        action: 'TOTP_SETUP_INITIATED',
        resource: 'mfa',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.json({
        success: true,
        message: 'Scanează QR code-ul cu Google Authenticator',
        qrCode,
        secret: secret.base32,
        otpauthUrl: secret.otpauth_url
      });
    } catch (error) {
      console.error('Eroare la setup TOTP:', error);
      res.status(500).json({ success: false, message: 'Eroare la inițierea setup-ului TOTP' });
    }
  }

  // Confirmare TOTP cu primul cod valid generat de authenticator app
  async confirmTOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const { token } = req.body;
      const userId = req.user.id;

      const result = await totpService.confirmAndActivate(userId, token);

      if (!result.success) {
        await auditLogger.log({
          userId,
          action: 'TOTP_CONFIRM_FAILED',
          resource: 'mfa',
          status: 'failure',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });
        return res.status(400).json(result);
      }

      await auditLogger.log({
        userId,
        action: 'TOTP_SETUP_CONFIRMED',
        resource: 'mfa',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      await autoEnableMFA(userId, req.ip, req.headers['user-agent']);

      res.json(result);
    } catch (error) {
      console.error('Eroare la confirmarea TOTP:', error);
      res.status(500).json({ success: false, message: 'Eroare la confirmarea TOTP' });
    }
  }

  // ── FIDO2/WebAuthn (W3C WebAuthn Level 2 + @simplewebauthn/server) ──────────

  async getFido2RegistrationOptions(req, res) {
    try {
      const userId = req.user.id;
      const user = await User.findById(userId);

      // Excludem credențialele deja înregistrate
      const existing = await MFA.getFido2Credential(userId);
      const excludeCredentials = existing
        ? [{ id: Buffer.from(existing.credential_id, 'base64url'), type: 'public-key' }]
        : [];

      const options = generateRegistrationOptions({
        rpName: 'MFA Auth System',
        rpID: RP_ID,
        userID: Buffer.from(String(userId)),
        userName: user.email,
        userDisplayName: user.username,
        attestationType: 'none',
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'preferred',
        },
        excludeCredentials,
      });

      challengeStore.set(userId, options.challenge);

      res.json({ success: true, options });
    } catch (error) {
      console.error('Eroare FIDO2 registration options:', error);
      res.status(500).json({ success: false, message: 'Eroare la generarea opțiunilor FIDO2' });
    }
  }

  async completeFido2Registration(req, res) {
    try {
      const userId = req.user.id;
      const { credential } = req.body;

      const expectedChallenge = challengeStore.get(userId);
      if (!expectedChallenge) {
        return res.status(400).json({ success: false, message: 'Challenge expirat — încearcă din nou' });
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          credential,
          expectedChallenge,
          expectedOrigin: ORIGIN,
          expectedRPID: RP_ID,
          requireUserVerification: true,
        });
      } catch (err) {
        return res.status(400).json({ success: false, message: err.message });
      }

      if (!verification.verified) {
        return res.status(400).json({ success: false, message: 'Verificare FIDO2 eșuată' });
      }

      challengeStore.delete(userId);

      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

      await MFA.addMethod({
        userId,
        methodType: 'fido2',
        credentialId: Buffer.from(credentialID).toString('base64url'),
        publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
      });

      // Setăm counterul inițial
      await MFA.updateFido2Counter(userId, counter);

      await auditLogger.log({
        userId,
        action: 'FIDO2_SETUP_CONFIRMED',
        resource: 'mfa',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      await autoEnableMFA(userId, req.ip, req.headers['user-agent']);

      res.json({ success: true, message: 'FIDO2 configurat cu succes!' });
    } catch (error) {
      console.error('Eroare completare FIDO2:', error);
      res.status(500).json({ success: false, message: 'Eroare la înregistrarea FIDO2' });
    }
  }

  // ── Gestionare generală ───────────────────────────────────────────────────

  async enableMFA(req, res) {
    try {
      const userId = req.user.id;
      const methods = await MFA.getUserMethods(userId);
      const activeMethods = methods.filter(m => m.is_enabled);

      if (activeMethods.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Configurează și confirmă cel puțin o metodă MFA înainte de activare'
        });
      }

      await User.toggleMFA(userId, true);

      const primaryMethod = activeMethods.find(m => m.is_primary);
      if (!primaryMethod) {
        await MFA.setPrimaryMethod(userId, activeMethods[0].method_type);
      }

      await auditLogger.log({
        userId,
        action: 'MFA_ENABLED',
        resource: 'mfa',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.json({ success: true, message: 'MFA activată cu succes' });
    } catch (error) {
      console.error('Eroare la activarea MFA:', error);
      res.status(500).json({ success: false, message: 'Eroare la activarea MFA' });
    }
  }

  async disableMFA(req, res) {
    try {
      const userId = req.user.id;
      await User.toggleMFA(userId, false);

      await auditLogger.log({
        userId,
        action: 'MFA_DISABLED',
        resource: 'mfa',
        status: 'warning',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.json({ success: true, message: 'MFA dezactivată' });
    } catch (error) {
      console.error('Eroare la dezactivarea MFA:', error);
      res.status(500).json({ success: false, message: 'Eroare la dezactivarea MFA' });
    }
  }

  async deleteMethod(req, res) {
    try {
      const userId = req.user.id;
      const { methodType } = req.params;

      const user = await User.findById(userId);
      const methods = await MFA.getUserMethods(userId);

      if (user.mfa_enabled && methods.length === 1) {
        return res.status(400).json({
          success: false,
          message: 'Nu poți șterge ultima metodă MFA cât timp MFA este activată'
        });
      }

      await MFA.deleteMethod(userId, methodType);

      await auditLogger.log({
        userId,
        action: 'MFA_METHOD_DELETED',
        resource: 'mfa',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { methodType }
      });

      res.json({ success: true, message: 'Metodă MFA ștearsă' });
    } catch (error) {
      console.error('Eroare la ștergerea metodei MFA:', error);
      res.status(500).json({ success: false, message: 'Eroare la ștergerea metodei MFA' });
    }
  }

  async setPrimaryMethod(req, res) {
    try {
      const userId = req.user.id;
      const { methodType } = req.body;

      await MFA.setPrimaryMethod(userId, methodType);

      await auditLogger.log({
        userId,
        action: 'MFA_PRIMARY_METHOD_CHANGED',
        resource: 'mfa',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { methodType }
      });

      res.json({ success: true, message: 'Metodă primară actualizată' });
    } catch (error) {
      console.error('Eroare la setarea metodei primare:', error);
      res.status(500).json({ success: false, message: 'Eroare la setarea metodei primare' });
    }
  }

  async generateBackupCodes(req, res) {
    try {
      const userId = req.user.id;
      const { methodType } = req.params;

      const result = await MFA.generateBackupCodes(userId, methodType);

      await auditLogger.log({
        userId,
        action: 'BACKUP_CODES_GENERATED',
        resource: 'mfa',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { methodType }
      });

      res.json({
        success: true,
        message: 'Coduri de backup generate. Salvează-le într-un loc sigur!',
        backupCodes: result.plainCodes
      });
    } catch (error) {
      console.error('Eroare la generarea codurilor de backup:', error);
      res.status(500).json({ success: false, message: 'Eroare la generarea codurilor de backup' });
    }
  }
}

module.exports = new MFAController();
