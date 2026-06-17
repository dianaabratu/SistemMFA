import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 10000
});

// Atașează token JWT la fiecare cerere
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('accessToken');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Refresh automat la 401
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      try {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) throw new Error('No refresh token');
        const res = await axios.post(`${API_BASE_URL}/auth/refresh-token`, { refreshToken });
        const { accessToken } = res.data;
        localStorage.setItem('accessToken', accessToken);
        original.headers.Authorization = `Bearer ${accessToken}`;
        return apiClient(original);
      } catch {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// Creează un client cu tempToken pentru fluxul MFA
const mfaStepClient = () => {
  const tempToken = localStorage.getItem('tempToken');
  return axios.create({
    baseURL: API_BASE_URL,
    headers: {
      'Content-Type': 'application/json',
      ...(tempToken ? { Authorization: `Bearer ${tempToken}` } : {})
    },
    timeout: 10000
  });
};

// ── Auth API ───────────────────────────────────────────────────────────────────
export const authAPI = {
  register: (data)     => apiClient.post('/auth/register', data),
  login:    (data)     => apiClient.post('/auth/login', data),
  logout:   ()         => apiClient.post('/auth/logout'),
  refreshToken: (rt)   => apiClient.post('/auth/refresh-token', { refreshToken: rt }),

  getProfile:   ()     => apiClient.get('/auth/profile'),
  getAuditLogs: (n=20) => apiClient.get(`/auth/audit-logs?limit=${n}`),

  // Al doilea factor MFA (folosesc tempToken)
  verifyTOTP:          (token)      => mfaStepClient().post('/auth/mfa/totp/verify',        { token }),
  verifyBackupCode:    (code)       => mfaStepClient().post('/auth/mfa/backup-code/verify', { code }),
  getFido2AuthOptions: ()           => mfaStepClient().get('/auth/mfa/fido2/options'),
  verifyFido2:         (credential) => mfaStepClient().post('/auth/mfa/fido2/verify',       { credential }),
};

// ── MFA Management API ─────────────────────────────────────────────────────────
export const mfaAPI = {
  getMethods:    ()           => apiClient.get('/mfa/methods'),

  setupTOTP:     ()           => apiClient.post('/mfa/setup/totp'),
  confirmTOTP:   (token)      => apiClient.post('/mfa/setup/totp/confirm', { token }),

  getFido2Options:   ()       => apiClient.get('/mfa/setup/fido2/options'),
  completeFido2:     (data)   => apiClient.post('/mfa/setup/fido2/complete', data),

  deleteMethod:  (methodType) => apiClient.delete(`/mfa/methods/${methodType}`),
  setPrimary:    (methodType) => apiClient.post('/mfa/primary', { methodType }),
  enableMFA:     ()           => apiClient.post('/mfa/enable'),
  disableMFA:    (password)   => apiClient.post('/mfa/disable', { password }),
  generateBackupCodes: (m)    => apiClient.post(`/mfa/backup-codes/${m}`),
};

export default apiClient;
