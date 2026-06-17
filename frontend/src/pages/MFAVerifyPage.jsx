import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { startAuthentication } from '@simplewebauthn/browser';
import { useAuth } from '../context/AuthContext';
import { authAPI } from '../services/api';
import toast from 'react-hot-toast';

const METHOD_META = {
  totp:  { icon: '📱', label: 'Authenticator App', placeholder: 'Cod din aplicație (6 cifre)' },
  fido2: { icon: '🔑', label: 'FIDO2 / WebAuthn',  placeholder: null },
};

export default function MFAVerifyPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { verifyTOTP, verifyFido2 } = useAuth();

  const state = location.state || {};
  const [activeMethod, setActiveMethod] = useState(state.primaryMethod || 'totp');
  const [availableMethods] = useState(
    (state.availableMethods || ['totp']).filter(m => m !== 'sms')
  );
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showBackup, setShowBackup] = useState(false);
  const [backupCode, setBackupCode] = useState('');

  useEffect(() => {
    const tempToken = localStorage.getItem('tempToken');
    if (!tempToken) navigate('/login', { replace: true });
  }, [navigate]);

  const handleVerify = async (e) => {
    e.preventDefault();
    setError('');
    if (code.length !== 6) { setError('Codul trebuie să aibă 6 cifre'); return; }
    setLoading(true);

    const result = await verifyTOTP(code);

    setLoading(false);
    if (!result.success) { setError(result.message); return; }
    toast.success('Autentificare completă!');
    navigate('/dashboard', { replace: true });
  };

  const handleFido2 = async () => {
    setError('');
    setLoading(true);
    try {
      const optRes = await authAPI.getFido2AuthOptions();
      const credential = await startAuthentication(optRes.data.options);
      const result = await verifyFido2(credential);
      if (!result.success) { setError(result.message); return; }
      toast.success('Autentificare FIDO2 completă!');
      navigate('/dashboard', { replace: true });
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        setError('Autentificarea a fost anulată sau dispozitivul nu a răspuns.');
      } else {
        setError(err.response?.data?.message || err.message || 'Eroare FIDO2');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyBackup = async (e) => {
    e.preventDefault();
    setError('');
    if (!backupCode.trim()) { setError('Introdu codul de backup'); return; }
    setLoading(true);

    try {
      const result = await authAPI.verifyBackupCode(backupCode.trim());
      const { accessToken, refreshToken, user } = result.data;
      localStorage.removeItem('tempToken');
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);
      localStorage.setItem('user', JSON.stringify(user));
      window.location.href = '/dashboard';
    } catch (err) {
      setError(err.response?.data?.message || 'Cod de backup invalid');
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    localStorage.removeItem('tempToken');
    navigate('/login', { replace: true });
  };

  if (showBackup) {
    return (
      <div className="page-center">
        <div className="card">
          <button className="btn btn-ghost btn-sm mb-4" onClick={() => { setShowBackup(false); setError(''); }}>
            ← Înapoi
          </button>
          <h2 className="mb-4">Cod de backup</h2>
          <p className="text-sm text-muted mb-4">
            Folosește unul din codurile de backup generate la configurarea MFA.
            Fiecare cod poate fi utilizat o singură dată.
          </p>
          <form onSubmit={handleVerifyBackup}>
            <div className="form-group">
              <label>Cod de backup</label>
              <input
                type="text"
                value={backupCode}
                onChange={e => setBackupCode(e.target.value.toUpperCase())}
                placeholder="XXXXXXXX"
                style={{ fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '.1em' }}
                autoFocus
              />
            </div>
            {error && <div className="alert alert-error">{error}</div>}
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? <><span className="spinner" />Se verifică...</> : 'Verifică'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  const meta = METHOD_META[activeMethod] || METHOD_META.totp;

  return (
    <div className="page-center">
      <div className="card">
        <div className="text-center mb-6">
          <h2>Alege metoda de autentificare</h2>
        </div>

        {availableMethods.length > 1 && (
          <div style={{ display: 'flex', gap: '.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            {availableMethods.map(m => (
              <button
                key={m}
                className={`btn btn-sm ${activeMethod === m ? 'btn-primary' : 'btn-secondary'}`}
                style={{ width: 'auto', flex: 1 }}
                onClick={() => { setActiveMethod(m); setCode(''); setError(''); }}
              >
                {METHOD_META[m]?.icon} {m.toUpperCase()}
              </button>
            ))}
          </div>
        )}

        {activeMethod === 'fido2' ? (
          <div>
            <div className="alert alert-info text-sm mb-4">
              Apasă butonul de mai jos și urmează instrucțiunile de pe dispozitivul tău.
            </div>
            {error && <div className="alert alert-error mb-3">{error}</div>}
            <button className="btn btn-primary" onClick={handleFido2} disabled={loading}>
              {loading
                ? <><span className="spinner" />Se verifică...</>
                : '🔑 Autentifică-te'}
            </button>
          </div>
        ) : (
          <>
            <div className="alert alert-info text-sm mb-4">
              Deschide aplicația Google Authenticator și introdu codul de 6 cifre.
            </div>
            <form onSubmit={handleVerify}>
              <div className="otp-group">
                {[0,1,2,3,4,5].map(i => (
                  <input
                    key={i}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    className="otp-input"
                    value={code[i] || ''}
                    autoFocus={i === 0}
                    onChange={ev => {
                      const val = ev.target.value.replace(/\D/g, '');
                      const chars = code.split('');
                      chars[i] = val;
                      setCode(chars.join('').slice(0, 6));
                      if (val && i < 5) ev.target.nextSibling?.focus();
                    }}
                    onKeyDown={ev => {
                      if (ev.key === 'Backspace' && !code[i] && i > 0)
                        ev.target.previousSibling?.focus();
                    }}
                  />
                ))}
              </div>
              {error && <div className="alert alert-error">{error}</div>}
              <button type="submit" className="btn btn-primary" disabled={loading || code.length !== 6}>
                {loading ? <><span className="spinner" />Se verifică...</> : 'Verifică'}
              </button>
            </form>
          </>
        )}

        <div className="divider mt-4">sau</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '.5rem' }}>
          <button className="btn btn-secondary btn-sm" onClick={() => setShowBackup(true)}>
            Folosește cod de backup
          </button>
          <button className="btn btn-ghost btn-sm" onClick={handleCancel}>
            Anulează autentificarea
          </button>
        </div>
      </div>
    </div>
  );
}
