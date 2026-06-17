const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const db = require('../config/database');

class TOTPService {
  // Generare secret TOTP nou
  generateSecret(userEmail) {
    const secret = speakeasy.generateSecret({
      name: `MFA Auth System (${userEmail})`,
      issuer: 'MFA Auth System',
      length: 20
    });
    return secret;
  }

  // Generare QR code pentru Google Authenticator
  async generateQRCode(otpauthUrl) {
    try {
      const qrCodeDataURL = await QRCode.toDataURL(otpauthUrl, {
        errorCorrectionLevel: 'H',
        type: 'image/png',
        quality: 0.92,
        margin: 1,
        width: 256
      });
      return qrCodeDataURL;
    } catch (error) {
      throw new Error('Nu s-a putut genera QR code-ul');
    }
  }

  // Verificare token TOTP
  verifyToken(secret, token) {
    return speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 1 // permite o fereastra de +/- 30 secunde
    });
  }

  // Salvare secret TOTP în baza de date (temporar, înainte de confirmare)
  async savePendingSecret(userId, secret) {
    const query = `
      INSERT INTO user_mfa_methods (user_id, method_type, secret_key, is_enabled)
      VALUES ($1, 'totp', $2, false)
      ON CONFLICT (user_id, method_type)
      DO UPDATE SET secret_key = $2, is_enabled = false, updated_at = CURRENT_TIMESTAMP
      RETURNING id
    `;
    const result = await db.query(query, [userId, secret]);
    return result.rows[0];
  }

  // Activare TOTP după confirmare cu token valid
  async confirmAndActivate(userId, token) {
    // Obținere secret pending
    const methodQuery = `
      SELECT secret_key FROM user_mfa_methods
      WHERE user_id = $1 AND method_type = 'totp'
    `;
    const methodResult = await db.query(methodQuery, [userId]);

    if (methodResult.rows.length === 0) {
      return { success: false, message: 'TOTP nu a fost configurat. Inițiază setup-ul mai întâi.' };
    }

    const secret = methodResult.rows[0].secret_key;

    // Verificare token
    const isValid = this.verifyToken(secret, token);
    if (!isValid) {
      return { success: false, message: 'Cod TOTP invalid. Verifică că ora dispozitivului este corectă.' };
    }

    // Activare metodă
    const updateQuery = `
      UPDATE user_mfa_methods
      SET is_enabled = true, updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $1 AND method_type = 'totp'
      RETURNING id
    `;
    await db.query(updateQuery, [userId]);

    return { success: true, message: 'TOTP activat cu succes' };
  }

  // Verificare token în cadrul autentificării
  async verifyForAuth(userId, token) {
    const query = `
      SELECT secret_key FROM user_mfa_methods
      WHERE user_id = $1 AND method_type = 'totp' AND is_enabled = true
    `;
    const result = await db.query(query, [userId]);

    if (result.rows.length === 0) {
      return { success: false, message: 'TOTP nu este configurat pentru acest cont' };
    }

    const secret = result.rows[0].secret_key;
    const isValid = this.verifyToken(secret, token);

    if (!isValid) {
      return { success: false, message: 'Cod TOTP invalid sau expirat' };
    }

    return { success: true };
  }
}

module.exports = new TOTPService();
