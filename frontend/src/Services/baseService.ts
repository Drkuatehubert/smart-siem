// src/Services/baseService.ts
import { axiosInstance, delay } from './apiClients';

export abstract class BaseService {
  protected client = axiosInstance;
  
  /**
   * Core central request wrapper with fallback to mock data
   */
  protected async request<T>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    url: string,
    data: any,
    fallbackAction: () => T
  ): Promise<T> {
    const hasConfiguredEndpoint = !!(import.meta as any).env.VITE_API_URL;
    const forceMock = (import.meta as any).env.VITE_FORCE_MOCK === 'true';

    if (!hasConfiguredEndpoint || forceMock) {
      return delay(fallbackAction());
    }

    try {
      const response = await this.client.request<T>({
        method,
        url,
        data,
      });
      return response.data;
    } catch (error: any) {
      console.warn(
        `[SIEM REST API - AUTO-FALLBACK] ${method} ${url} a échoué. Utilisation de la simulation locale.`,
        error.message || error
      );
      return delay(fallbackAction());
    }
  }

  // Helper pour les logs d'audit
  protected addAuditLog(
    logs: any[],
    user: string, 
    role: string, 
    action: string, 
    target: string, 
    status: 'SUCCESS' | 'FAILED'
  ) {
    const newLog = {
      id: `aud-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user,
      role,
      action,
      target,
      status,
      ip_address: '192.168.1.50'
    };
    logs.unshift(newLog);
    return logs;
  }
}