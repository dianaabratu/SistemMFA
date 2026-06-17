import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authAPI } from '../services/api';

export default function AuthCallbackPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  useEffect(() => {
    const handle = async () => {
      const error = params.get('error');
      if (error) {
        navigate(`/login?error=${error}`, { replace: true });
        return;
      }

      const tempToken = params.get('tempToken');
      if (tempToken) {
        localStorage.setItem('tempToken', tempToken);
        const primaryMethod = params.get('primaryMethod') || 'totp';
        const availableMethods = (params.get('availableMethods') || 'totp').split(',');
        navigate('/mfa/verify', { replace: true, state: { primaryMethod, availableMethods } });
        return;
      }

      const accessToken = params.get('accessToken');
      const refreshToken = params.get('refreshToken');
      if (accessToken && refreshToken) {
        localStorage.setItem('accessToken', accessToken);
        localStorage.setItem('refreshToken', refreshToken);
        try {
          const res = await authAPI.getProfile();
          localStorage.setItem('user', JSON.stringify(res.data.user));
        } catch {
          // dacă profile-ul eșuează, token-ul e totuși valid; dashboard-ul va reîncerca
        }
        navigate('/dashboard', { replace: true });
        return;
      }

      navigate('/login', { replace: true });
    };

    handle();
  }, []); // eslint-disable-line

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      height: '100vh', flexDirection: 'column', gap: '1rem',
    }}>
      <div className="spinner" style={{
        width: 40, height: 40, borderWidth: 3,
        borderColor: '#e5e7eb', borderTopColor: '#2563eb',
      }} />
      <p style={{ color: '#6b7280', fontSize: '.9rem' }}>Se procesează autentificarea...</p>
    </div>
  );
}
