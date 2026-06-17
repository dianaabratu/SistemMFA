-- Database: MFA Authentication System
-- Author: Diana-Roxana Bratu

-- Tabela pentru utilizatori
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255),          -- NULL pentru conturi Google-only
    google_id VARCHAR(255) UNIQUE,       -- ID unic Google (sub claim din ID token)
    phone_number VARCHAR(20),
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Tabela pentru metodele MFA ale utilizatorilor
CREATE TABLE IF NOT EXISTS user_mfa_methods (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method_type VARCHAR(50) NOT NULL, -- 'sms', 'totp', 'email', 'fido2'
    is_primary BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT TRUE,
    secret_key TEXT, -- Pentru TOTP
    phone_number VARCHAR(20), -- Pentru SMS
    credential_id TEXT, -- Pentru FIDO2
    public_key TEXT, -- Pentru FIDO2
    counter INTEGER DEFAULT 0, -- Pentru FIDO2
    backup_codes TEXT[], -- Coduri de backup
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, method_type)
);

-- Tabela pentru OTP-uri active
CREATE TABLE IF NOT EXISTS otp_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    method_type VARCHAR(50) NOT NULL,
    phone_number VARCHAR(20),
    email VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela pentru sesiuni
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    mfa_verified BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela pentru audit log
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20), -- 'success', 'failure', 'warning'
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela pentru încercări de autentificare eșuate
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(255)
);

-- Indexuri pentru performanță
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_user_mfa_methods_user_id ON user_mfa_methods(user_id);
CREATE INDEX IF NOT EXISTS idx_otp_codes_user_id ON otp_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_otp_codes_expires_at ON otp_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_failed_attempts_ip ON failed_login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_failed_attempts_time ON failed_login_attempts(attempt_time);

-- Funcție pentru actualizare automată a updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger pentru users
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger pentru user_mfa_methods
DROP TRIGGER IF EXISTS update_user_mfa_methods_updated_at ON user_mfa_methods;
CREATE TRIGGER update_user_mfa_methods_updated_at BEFORE UPDATE ON user_mfa_methods
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Curățare automată OTP-uri expirate (opțional, poate fi rulat periodic)
CREATE OR REPLACE FUNCTION cleanup_expired_otps()
RETURNS void AS $$
BEGIN
    DELETE FROM otp_codes WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Curățare automată sesiuni expirate
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Inserare date de test (opțional)
-- Parolă: Test123!@#
INSERT INTO users (email, username, password_hash, phone_number, is_verified, mfa_enabled) 
VALUES (
    'test@example.com', 
    'testuser', 
    '$2a$12$HBWiK/iUtGWp68HcK2NraufK6gjWUXSDZuSbfJ7wuFoFE9oh9Myya',
    '+40712345678',
    true,
    false
) ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, is_verified = EXCLUDED.is_verified;

COMMENT ON TABLE users IS 'Tabela principală pentru utilizatori';
COMMENT ON TABLE user_mfa_methods IS 'Metodele MFA configurate pentru fiecare utilizator';
COMMENT ON TABLE otp_codes IS 'Coduri OTP temporare generate pentru autentificare';
COMMENT ON TABLE sessions IS 'Sesiuni active ale utilizatorilor';
COMMENT ON TABLE audit_logs IS 'Log-uri pentru audit și securitate';
COMMENT ON TABLE failed_login_attempts IS 'Încercări eșuate de autentificare pentru detectarea atacurilor';
