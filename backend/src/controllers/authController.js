const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const { Issuer } = require('openid-client');
const { generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const User = require('../models/User');
const MFA = require('../models/MFA');
const totpService = require('../services/totpService');
const auditLogger = require('../utils/auditLogger');
const challengeStore = require('../utils/challengeStore');

const RP_ID = process.env.FIDO2_RP_ID || 'localhost';
const ORIGIN = process.env.FIDO2_ORIGIN || 'http://localhost:3000';
const FRONTEND_URL = process.env.CORS_ORIGIN || 'http://localhost:3000';

// ── Google OIDC client (inițializat lazy, cacheuit) ──────────────────────────
let _googleClient = null;
async function getGoogleClient() {
  if (_googleClient) return _googleClient;
  const issuer = await Issuer.discover('https://accounts.google.com');
  _googleClient = new issuer.Client({
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uris: [process.env.GOOGLE_REDIRECT_URI],
    response_types: ['code'],
  });
  return _googleClient;
}

// Store temporar pentru state OIDC (anti-CSRF), TTL 10 minute
const stateStore = new Map();
function newState() {
  const s = crypto.randomBytes(16).toString('hex');
  stateStore.set(s, Date.now() + 10 * 60 * 1000);
  return s;
}
function consumeState(s) {
  const exp = stateStore.get(s);
  if (!exp || Date.now() > exp) { stateStore.delete(s); return false; }
  stateStore.delete(s);
  return true;
}

const generateTokens = (userId) => ({
  accessToken: jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  }),
  refreshToken: jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN
  })
});

class AuthController {
  // Înregistrare utilizator nou
  async register(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const { email, username, password, phoneNumber } = req.body;

      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        return res.status(409).json({ success: false, message: 'Email-ul este deja înregistrat' });
      }

      const user = await User.create({ email, username, password, phoneNumber });

      await auditLogger.log({
        userId: user.id,
        action: 'USER_REGISTERED',
        resource: 'user',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.status(201).json({
        success: true,
        message: 'Cont creat cu succes',
        user: { id: user.id, email: user.email, username: user.username }
      });
    } catch (error) {
      console.error('Eroare la înregistrare:', error);
      res.status(500).json({ success: false, message: 'Eroare la înregistrarea utilizatorului' });
    }
  }

  // Autentificare — pasul 1: verificare parolă
  async login(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const { email, password } = req.body;

      const user = await User.findByEmail(email);
      if (!user) {
        await auditLogger.log({
          action: 'LOGIN_FAILED',
          resource: 'auth',
          status: 'failure',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          details: { reason: 'User not found', email }
        });
        return res.status(401).json({ success: false, message: 'Email sau parolă incorectă' });
      }

      if (!user.password_hash) {
        return res.status(401).json({
          success: false,
          message: 'Acest cont folosește autentificarea Google. Folosește butonul "Continuă cu Google".',
          googleOnly: true
        });
      }

      const isValidPassword = await User.verifyPassword(password, user.password_hash);
      if (!isValidPassword) {
        await auditLogger.log({
          userId: user.id,
          action: 'LOGIN_FAILED',
          resource: 'auth',
          status: 'failure',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          details: { reason: 'Invalid password' }
        });
        return res.status(401).json({ success: false, message: 'Email sau parolă incorectă' });
      }

      if (!user.is_active) {
        return res.status(403).json({ success: false, message: 'Contul este dezactivat' });
      }

      // Dacă MFA este activat, emitem un token temporar și cerem al doilea factor
      if (user.mfa_enabled) {
        const methods = await MFA.getUserMethods(user.id);
        const activeMethods = methods.filter(m => m.is_enabled);
        const primaryMethod = activeMethods.find(m => m.is_primary) || activeMethods[0];

        const tempToken = jwt.sign(
          { userId: user.id, mfaPending: true },
          process.env.JWT_SECRET,
          { expiresIn: '30m' }
        );

        await auditLogger.log({
          userId: user.id,
          action: 'LOGIN_MFA_REQUIRED',
          resource: 'auth',
          status: 'success',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          details: { primaryMethod: primaryMethod?.method_type }
        });

        return res.json({
          success: true,
          requireMFA: true,
          tempToken,
          primaryMethod: primaryMethod?.method_type || 'totp',
          availableMethods: activeMethods.map(m => m.method_type),
          message: 'Verificare MFA necesară'
        });
      }

      // Fără MFA — autentificare directă
      await User.updateLastLogin(user.id);
      const { accessToken, refreshToken } = generateTokens(user.id);

      await auditLogger.log({
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        resource: 'auth',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      res.json({
        success: true,
        message: 'Autentificare reușită',
        accessToken,
        refreshToken,
        user: { id: user.id, email: user.email, username: user.username, mfaEnabled: user.mfa_enabled }
      });
    } catch (error) {
      console.error('Eroare la autentificare:', error);
      res.status(500).json({ success: false, message: 'Eroare la autentificare' });
    }
  }

  // Verificare TOTP în fluxul de autentificare
  async verifyTOTP(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const { token } = req.body;
      const authHeader = req.headers['authorization'];
      const tempToken = authHeader && authHeader.split(' ')[1];

      if (!tempToken) {
        return res.status(401).json({ success: false, message: 'Token temporar lipsă' });
      }

      let decoded;
      try {
        decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
      } catch {
        return res.status(401).json({ success: false, message: 'Token temporar invalid sau expirat' });
      }

      if (!decoded.mfaPending) {
        return res.status(403).json({ success: false, message: 'Token invalid pentru MFA' });
      }

      const userId = decoded.userId;
      const verification = await totpService.verifyForAuth(userId, token);

      if (!verification.success) {
        await auditLogger.log({
          userId,
          action: 'MFA_TOTP_FAILED',
          resource: 'auth',
          status: 'failure',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });
        return res.status(401).json(verification);
      }

      const user = await User.findById(userId);
      await User.updateLastLogin(userId);
      const { accessToken, refreshToken } = generateTokens(userId);

      await auditLogger.log({
        userId,
        action: 'LOGIN_SUCCESS',
        resource: 'auth',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { method: 'totp' }
      });

      res.json({
        success: true,
        message: 'Autentificare MFA (TOTP) reușită',
        accessToken,
        refreshToken,
        user: { id: user.id, email: user.email, username: user.username, mfaEnabled: user.mfa_enabled }
      });
    } catch (error) {
      console.error('Eroare la verificarea TOTP:', error);
      res.status(500).json({ success: false, message: 'Eroare la verificarea TOTP' });
    }
  }

  // Verificare cod de backup
  async verifyBackupCode(req, res) {
    try {
      const { code } = req.body;
      const authHeader = req.headers['authorization'];
      const tempToken = authHeader && authHeader.split(' ')[1];

      if (!tempToken) {
        return res.status(401).json({ success: false, message: 'Token lipsă' });
      }

      let decoded;
      try {
        decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
      } catch {
        return res.status(401).json({ success: false, message: 'Token temporar invalid sau expirat' });
      }

      if (!decoded.mfaPending) {
        return res.status(403).json({ success: false, message: 'Token invalid pentru MFA' });
      }

      const userId = decoded.userId;
      const usedMethod = await MFA.useBackupCode(userId, code);

      if (!usedMethod) {
        await auditLogger.log({
          userId,
          action: 'BACKUP_CODE_FAILED',
          resource: 'auth',
          status: 'failure',
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        });
        return res.status(401).json({ success: false, message: 'Cod de backup invalid' });
      }

      const user = await User.findById(userId);
      await User.updateLastLogin(userId);
      const { accessToken, refreshToken } = generateTokens(userId);

      await auditLogger.log({
        userId,
        action: 'LOGIN_SUCCESS',
        resource: 'auth',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { method: 'backup_code' }
      });

      res.json({
        success: true,
        message: 'Autentificare cu cod de backup reușită',
        accessToken,
        refreshToken,
        user: { id: user.id, email: user.email, username: user.username, mfaEnabled: user.mfa_enabled }
      });
    } catch (error) {
      console.error('Eroare la verificarea codului de backup:', error);
      res.status(500).json({ success: false, message: 'Eroare la verificarea codului de backup' });
    }
  }

  // Profil utilizator curent
  async getProfile(req, res) {
    try {
      const user = await User.getUserStats(req.user.id);
      const methods = await MFA.getUserMethods(req.user.id);

      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          mfaEnabled: user.mfa_enabled,
          hasPassword: user.has_password,
          createdAt: user.created_at,
          lastLogin: user.last_login,
          activeSessions: parseInt(user.active_sessions),
          mfaMethodsCount: parseInt(user.mfa_methods_count)
        },
        mfaMethods: methods.map(m => ({
          type: m.method_type,
          isPrimary: m.is_primary,
          isEnabled: m.is_enabled,
          phoneNumber: m.phone_number ? `***${m.phone_number.slice(-4)}` : null,
          createdAt: m.created_at
        }))
      });
    } catch (error) {
      console.error('Eroare la obținerea profilului:', error);
      res.status(500).json({ success: false, message: 'Eroare la obținerea profilului' });
    }
  }

  // Log-uri de audit pentru utilizatorul curent
  async getAuditLogs(req, res) {
    try {
      const limit = Math.min(parseInt(req.query.limit) || 20, 100);
      const logs = await auditLogger.getUserLogs(req.user.id, limit);

      res.json({ success: true, logs });
    } catch (error) {
      console.error('Eroare la obținerea log-urilor:', error);
      res.status(500).json({ success: false, message: 'Eroare la obținerea log-urilor de audit' });
    }
  }

  // Generare opțiuni autentificare FIDO2 (al doilea factor)
  async getFido2AuthOptions(req, res) {
    try {
      const authHeader = req.headers['authorization'];
      const tempToken = authHeader && authHeader.split(' ')[1];
      if (!tempToken) return res.status(401).json({ success: false, message: 'Token lipsă' });

      let decoded;
      try { decoded = jwt.verify(tempToken, process.env.JWT_SECRET); }
      catch { return res.status(401).json({ success: false, message: 'Token temporar invalid' }); }
      if (!decoded.mfaPending) return res.status(403).json({ success: false, message: 'Token invalid pentru MFA' });

      const userId = decoded.userId;
      const credential = await MFA.getFido2Credential(userId);
      if (!credential) {
        return res.status(400).json({ success: false, message: 'Nu există credential FIDO2 înregistrat' });
      }

      const options = generateAuthenticationOptions({
        rpID: RP_ID,
        allowCredentials: [{
          id: Buffer.from(credential.credential_id, 'base64url'),
          type: 'public-key',
        }],
        userVerification: 'required',
      });

      challengeStore.set(userId, options.challenge);
      res.json({ success: true, options });
    } catch (error) {
      console.error('Eroare FIDO2 auth options:', error);
      res.status(500).json({ success: false, message: 'Eroare la generarea opțiunilor FIDO2' });
    }
  }

  // Verificare răspuns FIDO2 (al doilea factor)
  async verifyFido2(req, res) {
    try {
      const { credential } = req.body;
      const authHeader = req.headers['authorization'];
      const tempToken = authHeader && authHeader.split(' ')[1];
      if (!tempToken) return res.status(401).json({ success: false, message: 'Token lipsă' });

      let decoded;
      try { decoded = jwt.verify(tempToken, process.env.JWT_SECRET); }
      catch { return res.status(401).json({ success: false, message: 'Token temporar invalid' }); }
      if (!decoded.mfaPending) return res.status(403).json({ success: false, message: 'Token invalid pentru MFA' });

      const userId = decoded.userId;
      const expectedChallenge = challengeStore.get(userId);
      if (!expectedChallenge) {
        return res.status(400).json({ success: false, message: 'Challenge expirat — încearcă din nou' });
      }

      const storedCredential = await MFA.getFido2Credential(userId);
      if (!storedCredential) {
        return res.status(400).json({ success: false, message: 'Credential FIDO2 negăsit' });
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          credential,
          expectedChallenge,
          expectedOrigin: ORIGIN,
          expectedRPID: RP_ID,
          authenticator: {
            credentialID: Buffer.from(storedCredential.credential_id, 'base64url'),
            credentialPublicKey: Buffer.from(storedCredential.public_key, 'base64url'),
            counter: storedCredential.counter || 0,
          },
          requireUserVerification: true,
        });
      } catch (err) {
        return res.status(401).json({ success: false, message: err.message });
      }

      if (!verification.verified) {
        await auditLogger.log({ userId, action: 'FIDO2_AUTH_FAILED', resource: 'auth', status: 'failure', ipAddress: req.ip, userAgent: req.headers['user-agent'] });
        return res.status(401).json({ success: false, message: 'Verificare FIDO2 eșuată' });
      }

      challengeStore.delete(userId);
      await MFA.updateFido2Counter(userId, verification.authenticationInfo.newCounter);

      const user = await User.findById(userId);
      await User.updateLastLogin(userId);
      const { accessToken, refreshToken } = generateTokens(userId);

      await auditLogger.log({ userId, action: 'LOGIN_SUCCESS', resource: 'auth', status: 'success', ipAddress: req.ip, userAgent: req.headers['user-agent'], details: { method: 'fido2' } });

      res.json({
        success: true,
        message: 'Autentificare FIDO2 reușită',
        accessToken,
        refreshToken,
        user: { id: user.id, email: user.email, username: user.username, mfaEnabled: user.mfa_enabled },
      });
    } catch (error) {
      console.error('Eroare verificare FIDO2:', error);
      res.status(500).json({ success: false, message: 'Eroare la verificarea FIDO2' });
    }
  }

  // Refresh token
  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return res.status(401).json({ success: false, message: 'Refresh token lipsă' });
      }

      jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
        if (err) {
          return res.status(403).json({ success: false, message: 'Refresh token invalid' });
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
          return res.status(404).json({ success: false, message: 'Utilizatorul nu există' });
        }

        const newAccessToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
          expiresIn: process.env.JWT_EXPIRES_IN
        });

        res.json({ success: true, accessToken: newAccessToken });
      });
    } catch (error) {
      console.error('Eroare la refresh token:', error);
      res.status(500).json({ success: false, message: 'Eroare la reînnoirea token-ului' });
    }
  }

  // Logout
  async logout(req, res) {
    try {
      await auditLogger.log({
        userId: req.user.id,
        action: 'LOGOUT',
        resource: 'auth',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
      res.json({ success: true, message: 'Deconectare reușită' });
    } catch (error) {
      console.error('Eroare la logout:', error);
      res.status(500).json({ success: false, message: 'Eroare la deconectare' });
    }
  }

  // ── Google OIDC ─────────────────────────────────────────────────────────────

  // Pasul 1: redirecționează utilizatorul la Google
  async googleAuth(req, res) {
    try {
      const client = await getGoogleClient();
      const state = newState();
      const url = client.authorizationUrl({
        scope: 'openid email profile',
        state,
      });
      res.redirect(url);
    } catch (error) {
      console.error('Eroare la inițierea Google OIDC:', error);
      res.redirect(`${FRONTEND_URL}/login?error=google_unavailable`);
    }
  }

  // Pasul 2: Google redirecționează înapoi cu codul de autorizare
  async googleCallback(req, res) {
    try {
      const { state } = req.query;

      if (!consumeState(state)) {
        return res.redirect(`${FRONTEND_URL}/login?error=invalid_state`);
      }

      const client = await getGoogleClient();
      const params = client.callbackParams(req);
      const tokenSet = await client.callback(process.env.GOOGLE_REDIRECT_URI, params, { state });
      const userinfo = await client.userinfo(tokenSet.access_token);

      // Găsire sau creare utilizator
      let user = await User.findByGoogleId(userinfo.sub);

      if (!user) {
        const existing = await User.findByEmail(userinfo.email);
        if (existing) {
          // Cont local cu același email → legăm Google ID-ul
          await User.linkGoogleId(existing.id, userinfo.sub);
          user = existing;
        } else {
          // Cont nou creat din Google
          const base = (userinfo.email.split('@')[0]).replace(/[^a-z0-9]/gi, '');
          const username = base + '_' + crypto.randomBytes(3).toString('hex');
          user = await User.createFromGoogle({
            googleId: userinfo.sub,
            email: userinfo.email,
            username,
          });
        }
      }

      if (!user.is_active) {
        return res.redirect(`${FRONTEND_URL}/login?error=account_disabled`);
      }

      await auditLogger.log({
        userId: user.id,
        action: 'LOGIN_GOOGLE_OIDC',
        resource: 'auth',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { email: userinfo.email },
      });

      // Dacă MFA e activ → tempToken, redirect la MFAVerify
      if (user.mfa_enabled) {
        const methods = await MFA.getUserMethods(user.id);
        const active = methods.filter(m => m.is_enabled);
        const primary = active.find(m => m.is_primary) || active[0];

        const tempToken = jwt.sign(
          { userId: user.id, mfaPending: true },
          process.env.JWT_SECRET,
          { expiresIn: '30m' }
        );

        const qs = new URLSearchParams({
          tempToken,
          primaryMethod: primary?.method_type || 'totp',
          availableMethods: active.map(m => m.method_type).join(','),
        });
        return res.redirect(`${FRONTEND_URL}/auth/callback?${qs}`);
      }

      // Fără MFA → autentificare completă
      await User.updateLastLogin(user.id);
      const { accessToken, refreshToken } = generateTokens(user.id);

      await auditLogger.log({
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        resource: 'auth',
        status: 'success',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: { method: 'google_oidc' },
      });

      const qs = new URLSearchParams({ accessToken, refreshToken });
      return res.redirect(`${FRONTEND_URL}/auth/callback?${qs}`);
    } catch (error) {
      console.error('Eroare Google OIDC callback:', error);
      res.redirect(`${FRONTEND_URL}/login?error=google_auth_failed`);
    }
  }
}

module.exports = new AuthController();
