// src/Services/baseService.ts
import { axiosInstance } from './apiClients';

export abstract class BaseService {
  protected client = axiosInstance;

  /**
   * Central request wrapper — appelle toujours l'API réelle.
   * Le 4e paramètre est conservé pour compatibilité ascendante mais ignoré.
   */
  protected async request<T>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    url: string,
    data?: any,
    _fallbackAction?: () => T
  ): Promise<T> {
    const response = await this.client.request<T>({ method, url, data });
    return response.data;
  }

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
      ip_address: ''
    };
    logs.unshift(newLog);
    return logs;
  }
}
