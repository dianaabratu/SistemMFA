import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { authAPI, mfaAPI } from '../services/api';
import toast from 'react-hot-toast';

const METHOD_META = {
  totp:  { icon: '📱', label: 'TOTP', desc: 'Google Authenticator' },
  fido2: { icon: '🔑', label: 'FIDO2 / WebAuthn',         desc: 'Cheie hardware sau biometrie' },
};

const ACTION_LABELS = {
  LOGIN_SUCCESS:              { label: 'Autentificare reușită', color: 'green' },
  LOGIN_GOOGLE_OIDC:          { label: 'Autentificare Google',  color: 'blue'  },
  LOGIN_FAILED:               { label: 'Autentificare eșuată',  color: 'red'   },
  LOGIN_MFA_REQUIRED:         { label: 'MFA solicitat',          color: 'blue'  },
  MFA_ENABLED:                { label: 'MFA activată',           color: 'green' },
  MFA_DISABLED:               { label: 'MFA dezactivată',        color: 'red'   },
  TOTP_SETUP_CONFIRMED:       { label: 'TOTP configurat',        color: 'green' },
  BACKUP_CODES_GENERATED:     { label: 'Coduri backup generate', color: 'blue'  },
  LOGOUT:                     { label: 'Deconectare',            color: 'gray'  },
  USER_REGISTERED:            { label: 'Cont creat',             color: 'green' },
};

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [profile, setProfile] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loadingProfile, setLoadingProfile] = useState(true);
  const [disablingMFA, setDisablingMFA] = useState(false);
  const [showDisableModal, setShowDisableModal] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [backupCodes, setBackupCodes] = useState(null);
  const [generatingBackup, setGeneratingBackup] = useState(false);

  const fetchProfile = useCallback(async () => {
    try {
      const [profileRes, logsRes] = await Promise.all([
        authAPI.getProfile(),
        authAPI.getAuditLogs(15)
      ]);
      setProfile(profileRes.data);
      setLogs(logsRes.data.logs || []);
    } catch {
      toast.error('Eroare la încărcarea datelor');
    } finally {
      setLoadingProfile(false);
    }
  }, []);

  useEffect(() => { fetchProfile(); }, [fetchProfile]);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const handleEnableMFA = async () => {
    try {
      await mfaAPI.enableMFA();
      toast.success('MFA activată!');
      fetchProfile();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Eroare la activarea MFA');
    }
  };

  const handleDisableMFA = async () => {
    setDisablingMFA(true);
    try {
      await mfaAPI.disableMFA(disablePassword);
      toast.success('MFA dezactivată');
      setShowDisableModal(false);
      setDisablePassword('');
      fetchProfile();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Parolă incorectă');
    } finally {
      setDisablingMFA(false);
    }
  };

  const handleDeleteMethod = async (methodType) => {
    if (!window.confirm(`Ștergi metoda ${methodType.toUpperCase()}?`)) return;
    try {
      await mfaAPI.deleteMethod(methodType);
      toast.success('Metodă ștearsă');
      fetchProfile();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Eroare');
    }
  };

  const handleGenerateBackup = async (methodType) => {
    setGeneratingBackup(true);
    try {
      const res = await mfaAPI.generateBackupCodes(methodType);
      setBackupCodes(res.data.backupCodes);
      toast.success('Coduri de backup generate!');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Eroare');
    } finally {
      setGeneratingBackup(false);
    }
  };

  const formatDate = (d) => d ? new Date(d).toLocaleString('ro-RO') : '—';

  if (loadingProfile) {
    return (
      <div className="dashboard-shell">
        <div className="page-center" style={{ background: 'var(--gray-50)' }}>
          <div className="spinner" style={{ width: 40, height: 40, borderWidth: 3, borderColor: 'var(--gray-200)', borderTopColor: 'var(--blue-600)' }} />
        </div>
      </div>
    );
  }

  const mfaMethods = profile?.mfaMethods || [];
  const mfaEnabled = profile?.user?.mfaEnabled;

  return (
    <div className="dashboard-shell">
      {/* Topbar */}
      <nav className="topbar">
        <div className="topbar-brand">
          <span className="lock-icon">🔐</span>
          Sistem MFA
        </div>
        <div className="topbar-actions">
          <span className="text-sm text-muted">
            {user?.username || profile?.user?.username}
          </span>
<button className="btn btn-secondary btn-sm" onClick={handleLogout}>
            Deconectare
          </button>
        </div>
      </nav>

      <div className="main-content">
        {/* Statistici */}
        <div className="stats-grid">
          <div className="stat-card">
            <span className="stat-label">Status MFA</span>
            <span className={`badge ${mfaEnabled ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '1rem', padding: '.4rem .8rem' }}>
              {mfaEnabled ? '✅ Activă' : '❌ Inactivă'}
            </span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Metode configurate</span>
            <span className="stat-value">{mfaMethods.filter(m => m.isEnabled).length}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Ultima autentificare</span>
            <span className="text-sm">{formatDate(profile?.user?.lastLogin)}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Cont creat</span>
            <span className="text-sm">{formatDate(profile?.user?.createdAt)}</span>
          </div>
        </div>

        {/* Alert MFA inactiv */}
        {!mfaEnabled && (
          <div className="alert alert-warning mb-6">
            <strong>Contul tău nu este protejat cu MFA!</strong>{' '}
            Configurează cel puțin o metodă și activează MFA pentru securitate sporită.
          </div>
        )}

        {/* Metode MFA */}
        <div className="panel">
          <div className="flex items-center justify-between mb-4">
            <h2 className="section-title" style={{ marginBottom: 0 }}>Metode de autentificare</h2>
            <button className="btn btn-primary btn-sm" style={{ width: 'auto' }} onClick={() => navigate('/mfa/setup')}>
              + Adaugă metodă
            </button>
          </div>

          {mfaMethods.length === 0 ? (
            <div className="alert alert-info">
              Nu ai nicio metodă MFA configurată.
            </div>
          ) : (
            <div className="methods-grid">
              {mfaMethods.map(method => {
                const meta = METHOD_META[method.type] || { icon: '🔒', label: method.type, desc: '' };
                return (
                  <div key={method.type} className={`method-card ${method.isEnabled ? 'active' : ''}`}>
                    <div className="method-card-header">
                      <span className="method-icon">{meta.icon}</span>
                      <div style={{ display: 'flex', gap: '.4rem', alignItems: 'center' }}>
                        {method.isPrimary && <span className="badge badge-blue">Primară</span>}
                        <span className={`badge ${method.isEnabled ? 'badge-green' : 'badge-gray'}`}>
                          {method.isEnabled ? 'Activă' : 'Inactivă'}
                        </span>
                      </div>
                    </div>
                    <div>
                      <div style={{ fontWeight: 600 }}>{meta.label}</div>
                      <div className="text-sm text-muted">{meta.desc}</div>
                      {method.phoneNumber && (
                        <div className="text-sm text-muted mt-1">Tel: {method.phoneNumber}</div>
                      )}
                    </div>
                    <div className="method-card-actions">
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => handleGenerateBackup(method.type)}
                        disabled={generatingBackup}
                      >
                        Coduri backup
                      </button>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDeleteMethod(method.type)}
                      >
                        Șterge
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Coduri de backup afișate */}
          {backupCodes && (
            <div className="alert alert-warning mt-4">
              <strong>Salvează aceste coduri în siguranță — nu vor fi afișate din nou!</strong>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '.5rem', marginTop: '.75rem' }}>
                {backupCodes.map((code, i) => (
                  <div key={i} className="secret-box" style={{ textAlign: 'center' }}>{code}</div>
                ))}
              </div>
              <button className="btn btn-secondary btn-sm mt-3" onClick={() => setBackupCodes(null)}>
                Am salvat codurile
              </button>
            </div>
          )}
        </div>

        {/* Activare / Dezactivare MFA */}
        <div className="panel">
          <h2 className="section-title">Control MFA</h2>
          {mfaEnabled ? (
            <div className="flex items-center justify-between flex-wrap gap-2">
              <p className="text-sm text-muted">Autentificarea multifactor este activă. Dezactivarea reduce securitatea contului.</p>
              <button className="btn btn-danger btn-sm" onClick={() => setShowDisableModal(true)}>
                Dezactivează MFA
              </button>
            </div>
          ) : (
            <div className="flex items-center justify-between flex-wrap gap-2">
              <p className="text-sm text-muted">
                {mfaMethods.filter(m => m.isEnabled).length > 0
                  ? 'Ai metode configurate. Activează MFA pentru a proteja contul.'
                  : 'Configurează cel puțin o metodă MFA.'}
              </p>
              <button
                className="btn btn-primary btn-sm"
                style={{ width: 'auto' }}
                onClick={handleEnableMFA}
                disabled={mfaMethods.filter(m => m.isEnabled).length === 0}
              >
                Activează MFA
              </button>
            </div>
          )}
        </div>

        {/* Audit log */}
        <div className="panel">
          <h2 className="section-title">Jurnal de securitate (ultimele 15 acțiuni)</h2>
          {logs.length === 0 ? (
            <p className="text-sm text-muted">Nu există înregistrări.</p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="log-table">
                <thead>
                  <tr>
                    <th>Acțiune</th>
                    <th>Status</th>
                    <th>IP</th>
                    <th>Data</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map(log => {
                    const meta = ACTION_LABELS[log.action];
                    return (
                      <tr key={log.id}>
                        <td>{meta?.label || log.action}</td>
                        <td>
                          <span className={`badge badge-${
                            log.status === 'success' ? 'green' :
                            log.status === 'failure' ? 'red' :
                            log.status === 'warning' ? 'gray' : 'blue'
                          }`}>
                            {log.status}
                          </span>
                        </td>
                        <td className="text-xs" style={{ fontFamily: 'monospace' }}>{log.ip_address || '—'}</td>
                        <td className="text-xs">{formatDate(log.created_at)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Modal dezactivare MFA */}
      {showDisableModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50, padding: '1rem'
        }}>
          <div className="card" style={{ maxWidth: 380 }}>
            <h3 style={{ marginBottom: '.5rem' }}>Dezactivare MFA</h3>
            <p className="text-sm text-muted mb-4">
              Ești sigură că vrei să dezactivezi MFA? Contul tău va fi mai puțin protejat.
            </p>
            <div style={{ display: 'flex', gap: '.75rem' }}>
              <button className="btn btn-secondary" style={{ flex: 1 }} onClick={() => setShowDisableModal(false)}>
                Anulează
              </button>
              <button className="btn btn-danger" style={{ flex: 1 }} onClick={handleDisableMFA} disabled={disablingMFA}>
                {disablingMFA ? <><span className="spinner" />...</> : 'Dezactivează'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
