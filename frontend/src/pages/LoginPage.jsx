import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [form, setForm] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [serverError, setServerError] = useState(
    searchParams.get('error') === 'google_auth_failed' ? 'Autentificarea Google a eșuat. Încearcă din nou.' :
    searchParams.get('error') === 'account_disabled'   ? 'Contul este dezactivat.' : ''
  );

  const validate = () => {
    const e = {};
    if (!form.email) e.email = 'Email-ul este obligatoriu';
    else if (!/\S+@\S+\.\S+/.test(form.email)) e.email = 'Email invalid';
    if (!form.password) e.password = 'Parola este obligatorie';
    return e;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setServerError('');
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setErrors({});
    setLoading(true);

    const result = await login({ email: form.email, password: form.password });
    setLoading(false);

    if (!result.success) {
      setServerError(result.googleOnly ? '__google_only__' : result.message);
      return;
    }

    if (result.requireMFA) {
      toast.success('Parolă corectă. Verificare MFA necesară.');
      navigate('/mfa/verify', {
        state: {
          primaryMethod: result.primaryMethod,
          availableMethods: result.availableMethods
        }
      });
      return;
    }

    toast.success('Autentificare reușită!');
    navigate('/dashboard');
  };

  return (
    <div className="page-center">
      <div className="card">
        <div className="text-center mb-6">
          <div style={{ fontSize: '2.5rem', marginBottom: '.5rem' }}>🔐</div>
          <h1 style={{ fontSize: '1.5rem' }}>Autentificare</h1>
          <p className="text-sm text-muted mt-2">Sistem MFA — Disertație Diana-Roxana Bratu</p>
        </div>

        {serverError && serverError !== '__google_only__' && (
          <div className="alert alert-error">{serverError}</div>
        )}
        {serverError === '__google_only__' && (
          <div className="alert alert-warning" style={{ textAlign: 'center' }}>
            Acest cont folosește autentificarea Google.<br />
            Folosește butonul de mai jos pentru a te loga.
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              className={errors.email ? 'error' : ''}
              placeholder="utilizator@exemplu.com"
              value={form.email}
              onChange={ev => setForm(f => ({ ...f, email: ev.target.value }))}
              autoComplete="email"
            />
            {errors.email && <p className="error-text">{errors.email}</p>}
          </div>

          <div className="form-group">
            <label htmlFor="password">Parolă</label>
            <input
              id="password"
              type="password"
              className={errors.password ? 'error' : ''}
              placeholder="••••••••"
              value={form.password}
              onChange={ev => setForm(f => ({ ...f, password: ev.target.value }))}
              autoComplete="current-password"
            />
            {errors.password && <p className="error-text">{errors.password}</p>}
          </div>

          <button type="submit" className="btn btn-primary mt-2" disabled={loading}>
            {loading ? <><span className="spinner" />Se procesează...</> : 'Autentificare'}
          </button>
        </form>

        <div className="divider mt-4">sau</div>

        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => { window.location.href = `${API_BASE}/auth/google`; }}
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '.6rem', margin: '0 auto', width: 'fit-content' }}
        >
          <svg width="18" height="18" viewBox="0 0 48 48">
            <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
            <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
            <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
            <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
          </svg>
          Continuă cu Google
        </button>

        <p className="text-center text-sm text-muted mt-4">
          Nu ai cont?{' '}
          <Link to="/register" className="btn btn-ghost" style={{ display: 'inline', padding: '0' }}>
            Înregistrează-te
          </Link>
        </p>


      </div>
    </div>
  );
}
