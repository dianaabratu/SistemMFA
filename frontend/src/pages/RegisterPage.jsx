import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

const PASSWORD_RULES = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({ email: '', username: '', password: '', confirmPassword: '' });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [serverError, setServerError] = useState('');

  const validate = () => {
    const e = {};
    if (!form.email) e.email = 'Email-ul este obligatoriu';
    else if (!/\S+@\S+\.\S+/.test(form.email)) e.email = 'Email invalid';
    if (!form.username || form.username.length < 3) e.username = 'Username minim 3 caractere';
    if (!form.password) e.password = 'Parola este obligatorie';
    else if (!PASSWORD_RULES.test(form.password))
      e.password = 'Minim 8 caractere, literă mică, literă mare, cifră și caracter special (@$!%*?&#)';
    if (form.password !== form.confirmPassword) e.confirmPassword = 'Parolele nu coincid';
    return e;
  };

  const handleSubmit = async (ev) => {
    ev.preventDefault();
    setServerError('');
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setErrors({});
    setLoading(true);

    const payload = { email: form.email, username: form.username, password: form.password };

    const result = await register(payload);
    setLoading(false);

    if (!result.success) {
      setServerError(result.message);
      return;
    }

    toast.success('Cont creat cu succes! Autentifică-te.');
    navigate('/login');
  };

  const field = (id, label, type, placeholder) => (
    <div className="form-group">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        type={type}
        className={errors[id] ? 'error' : ''}
        placeholder={placeholder}
        value={form[id]}
        onChange={ev => setForm(f => ({ ...f, [id]: ev.target.value }))}
        autoComplete={id}
      />
      {errors[id] && <p className="error-text">{errors[id]}</p>}
    </div>
  );

  return (
    <div className="page-center">
      <div className="card card-wide">
        <div className="text-center mb-6">
          <div style={{ fontSize: '2.5rem', marginBottom: '.5rem' }}>🔑</div>
          <h1 style={{ fontSize: '1.5rem' }}>Creare cont</h1>
          <p className="text-sm text-muted mt-2">Înregistrează-te în sistemul MFA</p>
        </div>

        {serverError && <div className="alert alert-error">{serverError}</div>}

        <form onSubmit={handleSubmit}>
          {field('email', 'Email *', 'email', 'utilizator@exemplu.com')}
          {field('username', 'Nume utilizator *', 'text', 'nume_prenume')}
          {field('password', 'Parolă *', 'password', '••••••••')}

          <div className="form-group">
            <label htmlFor="confirmPassword">Confirmare parolă *</label>
            <input
              id="confirmPassword"
              type="password"
              className={errors.confirmPassword ? 'error' : ''}
              placeholder="••••••••"
              value={form.confirmPassword}
              onChange={ev => setForm(f => ({ ...f, confirmPassword: ev.target.value }))}
              autoComplete="new-password"
            />
            {errors.confirmPassword && <p className="error-text">{errors.confirmPassword}</p>}
          </div>

          <button type="submit" className="btn btn-primary mt-2" disabled={loading}>
            {loading ? <><span className="spinner" />Se creează contul...</> : 'Creare cont'}
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
            <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
          </svg>
          Continuă cu Google
        </button>

        <p className="text-center text-sm text-muted mt-4">
          Ai deja cont?{' '}
          <Link to="/login" style={{ color: 'var(--blue-600)', textDecoration: 'none', fontWeight: 500 }}>
            Autentifică-te
          </Link>
        </p>
      </div>
    </div>
  );
}
