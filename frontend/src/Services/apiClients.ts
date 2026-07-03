// src/Services/apiClient.ts
import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios';

const API_BASE_URL = (import.meta as any).env.VITE_API_URL || 'http://localhost:8000/api/v1';

export const axiosInstance: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 5000,
  headers: { 'Content-Type': 'application/json' },
});

// ── Request interceptor : attache le JWT sur toutes les requêtes ─────────────
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('siem_jwt_token');
    if (token) {
      config.headers = config.headers ?? {};
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Token refresh state ───────────────────────────────────────────────────────
let isRefreshing = false;
let pendingRequests: ((token: string) => void)[] = [];

function processPending(token: string): void {
  pendingRequests.forEach(cb => cb(token));
  pendingRequests = [];
}

function clearSession(): void {
  [
    'siem_jwt_token', 'siem_refresh_token',
    'siem_authenticated', 'siem_role', 'siem_email', 'siem_username',
  ].forEach(k => localStorage.removeItem(k));
  window.dispatchEvent(new CustomEvent('siem:unauthorized'));
}

// ── Response interceptor : 401 → tenter refresh, sinon logout ────────────────
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status !== 401) return Promise.reject(error);

    const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // Ne pas boucler sur les endpoints d'auth eux-mêmes
    const url: string = original.url ?? '';
    if (url.includes('/auth/refresh') || url.includes('/auth/login')) {
      clearSession();
      return Promise.reject(error);
    }

    const refreshToken = localStorage.getItem('siem_refresh_token');
    if (!refreshToken) {
      clearSession();
      return Promise.reject(error);
    }

    // Si une requête a déjà déclenché un refresh en cours, mettre en file
    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        pendingRequests.push((newToken: string) => {
          original.headers = original.headers ?? {};
          original.headers.Authorization = `Bearer ${newToken}`;
          axiosInstance(original).then(resolve as any).catch(reject);
        });
      });
    }

    // Éviter une double tentative sur la même requête
    if (original._retry) {
      clearSession();
      return Promise.reject(error);
    }

    original._retry = true;
    isRefreshing = true;

    try {
      // Appel direct axios (pas axiosInstance) pour éviter la boucle infinie
      const refreshResponse = await axios.post(
        `${API_BASE_URL}/auth/refresh`,
        { refresh_token: refreshToken },
        { headers: { 'Content-Type': 'application/json' } },
      );

      const newToken: string = refreshResponse.data.access_token;
      localStorage.setItem('siem_jwt_token', newToken);

      isRefreshing = false;
      processPending(newToken);

      original.headers = original.headers ?? {};
      original.headers.Authorization = `Bearer ${newToken}`;
      return axiosInstance(original);
    } catch {
      isRefreshing = false;
      pendingRequests = [];
      clearSession();
      return Promise.reject(error);
    }
  }
);

// Helper conservé pour compatibilité ascendante
export const delay = <T>(value: T): Promise<T> =>
  new Promise((resolve) => setTimeout(() => resolve(value), 350));
