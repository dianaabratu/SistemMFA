import { createContext, useState, useContext, useEffect } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    const accessToken = localStorage.getItem('accessToken');
    if (storedUser && accessToken) {
      setUser(JSON.parse(storedUser));
      setIsAuthenticated(true);
    }
    setLoading(false);
  }, []);

  const register = async (userData) => {
    try {
      const response = await authAPI.register(userData);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, message: error.response?.data?.message || 'Eroare la înregistrare' };
    }
  };

  const login = async (credentials) => {
    try {
      const response = await authAPI.login(credentials);
      const { accessToken, refreshToken, user: userData, requireMFA, tempToken, primaryMethod, availableMethods } = response.data;

      if (requireMFA) {
        localStorage.setItem('tempToken', tempToken);
        return { success: true, requireMFA: true, primaryMethod, availableMethods };
      }

      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);
      localStorage.setItem('user', JSON.stringify(userData));
      setUser(userData);
      setIsAuthenticated(true);
      return { success: true, user: userData };
    } catch (error) {
      return {
        success: false,
        message: error.response?.data?.message || 'Eroare la autentificare',
        googleOnly: error.response?.data?.googleOnly || false
      };
    }
  };

  const _completeMFALogin = (accessToken, refreshToken, userData) => {
    localStorage.removeItem('tempToken');
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
    localStorage.setItem('user', JSON.stringify(userData));
    setUser(userData);
    setIsAuthenticated(true);
  };

  const verifyTOTP = async (token) => {
    try {
      const response = await authAPI.verifyTOTP(token);
      const { accessToken, refreshToken, user: userData } = response.data;
      _completeMFALogin(accessToken, refreshToken, userData);
      return { success: true, user: userData };
    } catch (error) {
      return { success: false, message: error.response?.data?.message || 'Cod TOTP invalid' };
    }
  };

  const verifyFido2 = async (credential) => {
    try {
      const response = await authAPI.verifyFido2(credential);
      const { accessToken, refreshToken, user: userData } = response.data;
      _completeMFALogin(accessToken, refreshToken, userData);
      return { success: true, user: userData };
    } catch (error) {
      return { success: false, message: error.response?.data?.message || 'Autentificare FIDO2 eșuată' };
    }
  };

  const logout = async () => {
    try { await authAPI.logout(); } catch { /* ignorăm eroarea la logout */ }
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');
    localStorage.removeItem('tempToken');
    setUser(null);
    setIsAuthenticated(false);
  };

  const updateUser = (userData) => {
    setUser(userData);
    localStorage.setItem('user', JSON.stringify(userData));
  };

  return (
    <AuthContext.Provider value={{
      user, loading, isAuthenticated,
      register, login, logout, updateUser,
      verifyTOTP, verifyFido2,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth trebuie folosit în interiorul AuthProvider');
  return context;
};

export default AuthContext;
