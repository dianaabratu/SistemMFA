const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function initializeDatabase() {
  const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'postgres' // Conectare la baza postgres pentru a crea DB
  });

  try {
    console.log('🔄 Verificare existență bază de date...');

    // Verificare dacă baza de date există
    const checkDbQuery = `
      SELECT 1 FROM pg_database WHERE datname = $1
    `;
    const result = await pool.query(checkDbQuery, [process.env.DB_NAME]);

    if (result.rows.length === 0) {
      console.log('📦 Creare bază de date...');
      await pool.query(`CREATE DATABASE ${process.env.DB_NAME}`);
      console.log(`✅ Baza de date '${process.env.DB_NAME}' a fost creată`);
    } else {
      console.log(`ℹ️  Baza de date '${process.env.DB_NAME}' există deja`);
    }

    await pool.end();

    // Conectare la noua bază de date pentru a rula schema
    const appPool = new Pool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD
    });

    console.log('🔄 Rulare script schema...');
    const schemaPath = path.join(__dirname, '../../../database/schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    
    await appPool.query(schemaSql);
    console.log('✅ Schema a fost aplicată cu succes');

    await appPool.end();

    console.log('\n╔════════════════════════════════════════╗');
    console.log('║                                        ║');
    console.log('║   ✅ Baza de date a fost              ║');
    console.log('║      inițializată cu succes!          ║');
    console.log('║                                        ║');
    console.log('╚════════════════════════════════════════╝\n');

    console.log('📝 Poți acum să pornești serverul cu: npm run dev');
    console.log('📝 Date de test:');
    console.log('   Email: test@example.com');
    console.log('   Parolă: Test123!@#');

  } catch (error) {
    console.error('❌ Eroare la inițializarea bazei de date:', error.message);
    process.exit(1);
  }
}

// Rulare script
initializeDatabase();
