import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import { mfaAPI } from '../services/api';
import toast from 'react-hot-toast';

// ── TOTP Setup ─────────────────────────────────────────────────────────────────

function TOTPSetup({ onDone }) {
  const [step, setStep] = useState('init'); // init | scan | confirm
  const [qrData, setQrData] = useState(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleStart = async () => {
    setLoading(true);
    try {
      const res = await mfaAPI.setupTOTP();
      setQrData(res.data);
      setStep('scan');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Eroare la inițierea TOTP');
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async (e) => {
    e.preventDefault();
    setError('');
    if (token.length !== 6) { setError('Codul trebuie să aibă 6 cifre'); return; }
    setLoading(true);
    try {
      await mfaAPI.confirmTOTP(token);
      toast.success('TOTP configurat cu succes!');
      setStep('done');
    } catch (err) {
      setError(err.response?.data?.message || 'Cod invalid');
    } finally {
      setLoading(false);
    }
  };

  if (step === 'init') {
    return (
      <div>
        <p className="text-sm text-muted mb-4">
          TOTP (Time-based One-Time Password) generează coduri de 6 cifre, care se schimbă la fiecare 30 de secunde. Compatibil cu Google Authenticator.
        </p>
        <div className="alert alert-info text-sm mb-4" style={{ textAlign: 'justify' }}>
          <strong>Securitate sporită:</strong> Codul este generat direct în aplicație, fără SMS și fără conexiune la internet, ceea ce îl face mai sigur împotriva interceptării. Este o metodă recomandată de standardele moderne de securitate.
        </div>
        <button className="btn btn-primary" onClick={handleStart} disabled={loading}>
          {loading ? <><span className="spinner" />Se generează...</> : 'Generează codul QR'}
        </button>
      </div>
    );
  }

  if (step === 'scan') {
    return (
      <div>
        <p className="text-sm text-muted mb-3">
          <strong>Pasul 1:</strong> Deschide Google Authenticator și scanează codul QR:
        </p>
        <div className="qr-wrapper">
          <img src={qrData.qrCode} alt="QR Code TOTP" width={200} height={200} />
        </div>
        <p className="text-sm text-muted mb-2">
          Sau introdu manual cheia secretă în aplicație:
        </p>
        <div className="secret-box mb-4">{qrData.secret}</div>

        <p className="text-sm text-muted mb-2">
          <strong>Pasul 2:</strong> Introdu codul de 6 cifre afișat în aplicație pentru confirmare:
        </p>
        <form onSubmit={handleConfirm}>
          <div className="otp-group">
            {[0,1,2,3,4,5].map(i => (
              <input
                key={i}
                type="text"
                inputMode="numeric"
                maxLength={1}
                className="otp-input"
                value={token[i] || ''}
                onChange={ev => {
                  const val = ev.target.value.replace(/\D/g, '');
                  const chars = token.split('');
                  chars[i] = val;
                  setToken(chars.join('').slice(0, 6));
                  if (val && i < 5) ev.target.nextSibling?.focus();
                }}
                onKeyDown={ev => {
                  if (ev.key === 'Backspace' && !token[i] && i > 0)
                    ev.target.previousSibling?.focus();
                }}
              />
            ))}
          </div>
          {error && <p className="error-text text-center mb-3">{error}</p>}
          <button type="submit" className="btn btn-primary" disabled={loading || token.length !== 6}>
            {loading ? <><span className="spinner" />Se verifică...</> : 'Confirmă TOTP'}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="text-center">
      <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>✅</div>
      <h3>TOTP configurat cu succes!</h3>
      <button className="btn btn-primary mt-4" onClick={onDone}>Înapoi la pagina principală</button>
    </div>
  );
}

// ── FIDO2 Setup ────────────────────────────────────────────────────────────────

function FIDO2Setup({ onDone }) {
  const [step, setStep] = useState('init'); // init | done | error
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleRegister = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      // 1. Obține opțiunile de înregistrare de la server
      const optRes = await mfaAPI.getFido2Options();
      const options = optRes.data.options;

      // 2. Browserul deschide promptul WebAuthn (Windows Hello / TouchID)
      const credential = await startRegistration(options);

      // 3. Trimite răspunsul înapoi la server pentru verificare
      await mfaAPI.completeFido2({ credential });

      toast.success('FIDO2 configurat cu succes!');
      setStep('done');
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        setErrorMsg('Autentificarea a fost anulată sau dispozitivul nu a răspuns.');
      } else {
        setErrorMsg(err.response?.data?.message || err.message || 'Eroare la înregistrarea FIDO2');
      }
    } finally {
      setLoading(false);
    }
  };

  if (step === 'done') {
    return (
      <div className="text-center">
        <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔑</div>
        <h3>FIDO2 configurat cu succes!</h3>
        <p className="text-sm text-muted mt-2 mb-4">
          Pentru următoarea autentificare vei folosi dispozitivul ales.
        </p>
        <button className="btn btn-primary" onClick={onDone}>Înapoi la pagina principală</button>
      </div>
    );
  }

  return (
    <div>
      <p className="text-sm text-muted mb-4" style={{ textAlign: 'justify' }}>
        FIDO2 / WebAuthn oferă una dintre cele mai sigure metode de autentificare.
        Folosește securitatea integrată a dispozitivului tău (amprentă, Face ID, PIN sau cheie hardware), fără a trimite parole sau coduri prin internet.
      </p>
      <div style={{ background: 'var(--gray-50)', borderRadius: 'var(--radius)', padding: '1rem', marginBottom: '1.25rem' }}>
        <p className="text-sm" style={{ fontWeight: 600, marginBottom: '.5rem' }}>Caracteristici:</p>
        <ul className="text-sm text-muted" style={{ paddingLeft: '1.25rem', lineHeight: 1.8 }}>
          <li>Rezistent la phishing</li>
          <li>Parolele și codurile nu sunt transmise prin internet</li>
          <li>Criptografie cu cheie publică</li>
          <li>Suportat nativ în Chrome, Firefox, Safari, Edge</li>
        </ul>
      </div>
      <div className="alert alert-warning text-sm mb-4">
        Asigură-te că ai un dispozitiv cu: Windows Hello, TouchID sau FaceID.
      </div>
      {errorMsg && <div className="alert alert-error mb-4">{errorMsg}</div>}
      <button className="btn btn-primary" onClick={handleRegister} disabled={loading}>
        {loading ? <><span className="spinner" />Se activează dispozitivul...</> : '🔑 Înregistrează dispozitivul'}
      </button>
    </div>
  );
}

// ── Pagina principală ──────────────────────────────────────────────────────────

const TABS = [
  { id: 'totp',  icon: '📱', label: 'TOTP', component: TOTPSetup  },
  { id: 'fido2', icon: '🔑', label: 'FIDO2 / WebAuthn',  component: FIDO2Setup },
];

export default function MFASetupPage() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('totp');

  const ActiveComponent = TABS.find(t => t.id === activeTab)?.component;

  return (
    <div className="page-center" style={{ alignItems: 'flex-start', paddingTop: '3rem' }}>
      <div className="card card-wide">
        <div className="flex items-center justify-between mb-6">
          <h2>Configurare MFA</h2>
          <button className="btn btn-ghost btn-sm" onClick={() => navigate('/dashboard')}>
            ← Pagina principală
          </button>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', borderBottom: '2px solid var(--gray-200)', marginBottom: '1.5rem' }}>
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: '.6rem 1rem',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                fontWeight: activeTab === tab.id ? 700 : 400,
                color: activeTab === tab.id ? 'var(--blue-600)' : 'var(--gray-600)',
                borderBottom: activeTab === tab.id ? '2px solid var(--blue-600)' : '2px solid transparent',
                marginBottom: -2,
                fontSize: '.875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '.4rem',
              }}
            >
              {tab.icon} {tab.label}
            </button>
          ))}
        </div>

        {ActiveComponent && (
          <ActiveComponent onDone={() => navigate('/dashboard')} />
        )}
      </div>
    </div>
  );
}
