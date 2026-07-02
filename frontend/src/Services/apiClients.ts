// src/Services/apiClient.ts
import axios, { type AxiosInstance } from 'axios';

// Base URL configurable via environment variables
const API_BASE_URL = (import.meta as any).env.VITE_API_URL || 'https://api.siem-defense.local/v1';

// Create a unique, centralized Axios instance
export const axiosInstance: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor: Automatically inject JWT Bearer Token
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('siem_jwt_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Interceptor: Handle expired/invalid JWT tokens (401 Unauthorized)
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      console.warn('[JWT SYSTEM] Session expirée ou non autorisée. Nettoyage de la session...');
      localStorage.removeItem('siem_jwt_token');
      localStorage.removeItem('siem_authenticated');
      localStorage.removeItem('siem_role');
      localStorage.removeItem('siem_email');
      
      const event = new CustomEvent('siem:unauthorized');
      window.dispatchEvent(event);
    }
    return Promise.reject(error);
  }
);

// Helper: Delay for mock simulation (350ms)
export const delay = <T>(value: T): Promise<T> => {
  return new Promise((resolve) => setTimeout(() => resolve(value), 350));
};