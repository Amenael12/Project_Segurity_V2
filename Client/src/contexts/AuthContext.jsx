import React, { createContext, useState, useContext, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      api.get('profile/')
        .then(response => setUser(response.data))
        .catch(() => {
          localStorage.removeItem('token');
          setUser(null);
        });
    }
  }, []);

  const login = async (credentials) => {
    try {
      const response = await api.post('login/', credentials);
      const { token, user_id, email } = response.data;
      localStorage.setItem('token', token);
      setUser({ id: user_id, email });
      api.defaults.headers.common['Authorization'] = `Token ${token}`;
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  };


  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);