const db = require('../config/database');

class AuditLogger {
  // Log acțiune în baza de date
  async log({ userId = null, action, resource, status = 'success', ipAddress = null, userAgent = null, details = null }) {
    try {
      const query = `
        INSERT INTO audit_logs (user_id, action, resource, status, ip_address, user_agent, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, created_at
      `;

      const result = await db.query(query, [
        userId,
        action,
        resource,
        status,
        ipAddress,
        userAgent,
        details ? JSON.stringify(details) : null
      ]);

      return result.rows[0];
    } catch (error) {
      console.error('Eroare la logging audit:', error);
      // Nu aruncăm eroare pentru a nu întrerupe fluxul aplicației
    }
  }

  // Obținere log-uri pentru utilizator
  async getUserLogs(userId, limit = 50) {
    const query = `
      SELECT id, action, resource, status, ip_address, created_at, details
      FROM audit_logs
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2
    `;

    const result = await db.query(query, [userId, limit]);
    return result.rows;
  }

  // Obținere încercări eșuate de autentificare
  async getFailedAttempts(identifier, hours = 1) {
    const query = `
      SELECT COUNT(*) as count
      FROM failed_login_attempts
      WHERE (email = $1 OR ip_address = $1)
        AND attempt_time > NOW() - INTERVAL '${hours} hours'
    `;

    const result = await db.query(query, [identifier]);
    return parseInt(result.rows[0].count);
  }

  // Log încercare eșuată
  async logFailedAttempt(email, ipAddress, reason) {
    const query = `
      INSERT INTO failed_login_attempts (email, ip_address, reason)
      VALUES ($1, $2, $3)
      RETURNING id
    `;

    const result = await db.query(query, [email, ipAddress, reason]);
    return result.rows[0];
  }

  // Curățare log-uri vechi
  async cleanupOldLogs(daysToKeep = 90) {
    const query = `
      DELETE FROM audit_logs
      WHERE created_at < NOW() - INTERVAL '${daysToKeep} days'
      RETURNING id
    `;

    const result = await db.query(query);
    console.log(`🧹 ${result.rowCount} log-uri vechi au fost șterse`);
    return result.rowCount;
  }
}

module.exports = new AuditLogger();
