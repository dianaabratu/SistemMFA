const db = require('../config/database');
const bcrypt = require('bcryptjs');

class User {
  // Creare utilizator nou
  static async create({ email, username, password, phoneNumber }) {
    const passwordHash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    
    const query = `
      INSERT INTO users (email, username, password_hash, phone_number)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, username, phone_number, is_verified, mfa_enabled, created_at
    `;
    
    const result = await db.query(query, [email, username, passwordHash, phoneNumber]);
    return result.rows[0];
  }

  // Găsire utilizator după email
  static async findByEmail(email) {
    const query = `
      SELECT id, email, username, password_hash, phone_number, is_verified, 
             is_active, mfa_enabled, created_at, updated_at, last_login
      FROM users
      WHERE email = $1
    `;
    
    const result = await db.query(query, [email]);
    return result.rows[0];
  }

  // Găsire utilizator după ID
  static async findById(id) {
    const query = `
      SELECT id, email, username, phone_number, is_verified, 
             is_active, mfa_enabled, created_at, updated_at, last_login
      FROM users
      WHERE id = $1
    `;
    
    const result = await db.query(query, [id]);
    return result.rows[0];
  }

  // Găsire utilizator după username
  static async findByUsername(username) {
    const query = `
      SELECT id, email, username, phone_number, is_verified, 
             is_active, mfa_enabled, created_at, updated_at, last_login
      FROM users
      WHERE username = $1
    `;
    
    const result = await db.query(query, [username]);
    return result.rows[0];
  }

  // Verificare parolă
  static async verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
  }

  // Actualizare ultima autentificare
  static async updateLastLogin(userId) {
    const query = `
      UPDATE users
      SET last_login = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING last_login
    `;
    
    const result = await db.query(query, [userId]);
    return result.rows[0];
  }

  // Activare/dezactivare MFA
  static async toggleMFA(userId, enabled) {
    const query = `
      UPDATE users
      SET mfa_enabled = $2
      WHERE id = $1
      RETURNING id, mfa_enabled
    `;
    
    const result = await db.query(query, [userId, enabled]);
    return result.rows[0];
  }

  // Verificare email
  static async verifyEmail(userId) {
    const query = `
      UPDATE users
      SET is_verified = true
      WHERE id = $1
      RETURNING id, is_verified
    `;
    
    const result = await db.query(query, [userId]);
    return result.rows[0];
  }

  // Actualizare telefon
  static async updatePhoneNumber(userId, phoneNumber) {
    const query = `
      UPDATE users
      SET phone_number = $2
      WHERE id = $1
      RETURNING id, phone_number
    `;
    
    const result = await db.query(query, [userId, phoneNumber]);
    return result.rows[0];
  }

  // Actualizare parolă
  static async updatePassword(userId, newPassword) {
    const passwordHash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    
    const query = `
      UPDATE users
      SET password_hash = $2
      WHERE id = $1
      RETURNING id
    `;
    
    const result = await db.query(query, [userId, passwordHash]);
    return result.rows[0];
  }

  // Găsire utilizator după Google ID
  static async findByGoogleId(googleId) {
    const query = `
      SELECT id, email, username, is_active, mfa_enabled
      FROM users WHERE google_id = $1
    `;
    const result = await db.query(query, [googleId]);
    return result.rows[0];
  }

  // Creare cont din Google OIDC (fără parolă locală)
  static async createFromGoogle({ googleId, email, username }) {
    const query = `
      INSERT INTO users (email, username, google_id, is_verified)
      VALUES ($1, $2, $3, true)
      RETURNING id, email, username, is_active, mfa_enabled
    `;
    const result = await db.query(query, [email, username, googleId]);
    return result.rows[0];
  }

  // Legare cont existent de Google ID (account linking)
  static async linkGoogleId(userId, googleId) {
    await db.query('UPDATE users SET google_id = $2 WHERE id = $1', [userId, googleId]);
  }

  // Ștergere utilizator
  static async delete(userId) {
    const query = `
      DELETE FROM users
      WHERE id = $1
      RETURNING id
    `;
    
    const result = await db.query(query, [userId]);
    return result.rows[0];
  }

  // Obținere statistici utilizator
  static async getUserStats(userId) {
    const query = `
      SELECT 
        u.id,
        u.email,
        u.username,
        u.mfa_enabled,
        u.created_at,
        u.last_login,
        (u.password_hash IS NOT NULL) as has_password,
        COUNT(DISTINCT s.id) as active_sessions,
        COUNT(DISTINCT umm.id) as mfa_methods_count
      FROM users u
      LEFT JOIN sessions s ON u.id = s.user_id AND s.expires_at > CURRENT_TIMESTAMP
      LEFT JOIN user_mfa_methods umm ON u.id = umm.user_id AND umm.is_enabled = true
      WHERE u.id = $1
      GROUP BY u.id
    `;
    
    const result = await db.query(query, [userId]);
    return result.rows[0];
  }
}

module.exports = User;
