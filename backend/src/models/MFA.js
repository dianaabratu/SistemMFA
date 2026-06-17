const db = require('../config/database');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

class MFA {
  // Adăugare metodă MFA
  static async addMethod({ userId, methodType, secretKey, phoneNumber, credentialId, publicKey }) {
    const query = `
      INSERT INTO user_mfa_methods (user_id, method_type, secret_key, phone_number, credential_id, public_key)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (user_id, method_type) 
      DO UPDATE SET 
        secret_key = EXCLUDED.secret_key,
        phone_number = EXCLUDED.phone_number,
        credential_id = EXCLUDED.credential_id,
        public_key = EXCLUDED.public_key,
        is_enabled = true,
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `;
    
    const result = await db.query(query, [
      userId, methodType, secretKey, phoneNumber, credentialId, publicKey
    ]);
    return result.rows[0];
  }

  // Obținere metode MFA pentru utilizator
  static async getUserMethods(userId) {
    const query = `
      SELECT id, method_type, is_primary, is_enabled, phone_number, created_at
      FROM user_mfa_methods
      WHERE user_id = $1
      ORDER BY is_primary DESC, created_at ASC
    `;
    
    const result = await db.query(query, [userId]);
    return result.rows;
  }

  // Obținere metodă specifică
  static async getMethod(userId, methodType) {
    const query = `
      SELECT *
      FROM user_mfa_methods
      WHERE user_id = $1 AND method_type = $2
    `;
    
    const result = await db.query(query, [userId, methodType]);
    return result.rows[0];
  }

  // Setare metodă primară
  static async setPrimaryMethod(userId, methodType) {
    const client = await db.pool.connect();
    
    try {
      await client.query('BEGIN');
      
      // Resetare toate metodele ca non-primare
      await client.query(
        'UPDATE user_mfa_methods SET is_primary = false WHERE user_id = $1',
        [userId]
      );
      
      // Setare metodă nouă ca primară
      const result = await client.query(
        'UPDATE user_mfa_methods SET is_primary = true WHERE user_id = $1 AND method_type = $2 RETURNING *',
        [userId, methodType]
      );
      
      await client.query('COMMIT');
      return result.rows[0];
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  // Activare/dezactivare metodă
  static async toggleMethod(userId, methodType, enabled) {
    const query = `
      UPDATE user_mfa_methods
      SET is_enabled = $3
      WHERE user_id = $1 AND method_type = $2
      RETURNING *
    `;
    
    const result = await db.query(query, [userId, methodType, enabled]);
    return result.rows[0];
  }

  // Ștergere metodă MFA
  static async deleteMethod(userId, methodType) {
    const query = `
      DELETE FROM user_mfa_methods
      WHERE user_id = $1 AND method_type = $2
      RETURNING id
    `;
    
    const result = await db.query(query, [userId, methodType]);
    return result.rows[0];
  }

  // Generare coduri de backup
  static async generateBackupCodes(userId, methodType) {
    // Generare criptografic sigura: 5 bytes => 10 caractere hex => format XXXXX-XXXXX
    const plainCodes = Array.from({ length: 10 }, () => {
      const hex = crypto.randomBytes(5).toString('hex').toUpperCase();
      return `${hex.slice(0, 5)}-${hex.slice(5)}`;
    });

    // Stocare hash-uita — daca DB e compromisa, codurile nu sunt expuse
    const hashedCodes = await Promise.all(
      plainCodes.map(code => bcrypt.hash(code, 10))
    );

    await db.query(
      `UPDATE user_mfa_methods
       SET backup_codes = $3
       WHERE user_id = $1 AND method_type = $2`,
      [userId, methodType, hashedCodes]
    );

    // Returnam codurile plain o singura data — nu sunt stocate nicaieri altundeva
    return { plainCodes };
  }

  // Verificare și utilizare cod de backup
  static async useBackupCode(userId, code) {
    // Incarcam toate hash-urile — nu putem face WHERE cu bcrypt
    const result = await db.query(
      `SELECT id, method_type, backup_codes
       FROM user_mfa_methods
       WHERE user_id = $1
         AND backup_codes IS NOT NULL
         AND array_length(backup_codes, 1) > 0`,
      [userId]
    );

    for (const method of result.rows) {
      for (const hash of method.backup_codes) {
        const match = await bcrypt.compare(code.toUpperCase(), hash);
        if (match) {
          // Stergem doar hash-ul potrivit
          await db.query(
            `UPDATE user_mfa_methods
             SET backup_codes = array_remove(backup_codes, $2)
             WHERE id = $1`,
            [method.id, hash]
          );
          return method;
        }
      }
    }

    return null;
  }

  // Obținere credential FIDO2 complet (pentru autentificare)
  static async getFido2Credential(userId) {
    const query = `
      SELECT credential_id, public_key, counter
      FROM user_mfa_methods
      WHERE user_id = $1 AND method_type = 'fido2' AND is_enabled = true
    `;
    const result = await db.query(query, [userId]);
    return result.rows[0];
  }

  // Actualizare counter după autentificare FIDO2
  static async updateFido2Counter(userId, newCounter) {
    const query = `
      UPDATE user_mfa_methods
      SET counter = $2
      WHERE user_id = $1 AND method_type = 'fido2'
    `;
    await db.query(query, [userId, newCounter]);
  }

  // Incrementare counter pentru FIDO2
  static async incrementFido2Counter(userId) {
    const query = `
      UPDATE user_mfa_methods
      SET counter = counter + 1
      WHERE user_id = $1 AND method_type = 'fido2'
      RETURNING counter
    `;
    const result = await db.query(query, [userId]);
    return result.rows[0];
  }
}

module.exports = MFA;
