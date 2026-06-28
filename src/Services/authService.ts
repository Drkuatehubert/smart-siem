// src/Services/authService.ts
import { BaseService } from './baseService';
import type { User, UserRole } from '../types';

export class AuthService extends BaseService {
  async login(email: string, password?: string): Promise<{ token: string; user: User }> {
    return this.request(
      'POST',
      '/auth/login',
      { email, password },
      () => {
        let assignedRole: UserRole = 'SOC_ANALYST';
        let name = 'Jean Dupont';
        if (email.includes('admin') || email.includes('pierre')) {
          assignedRole = 'ADMIN';
          name = 'Pierre Durand';
        } else if (email.includes('rssi') || email.includes('marc')) {
          assignedRole = 'RSSI';
          name = 'Marc Lemaire';
        } else if (email.includes('audit') || email.includes('externe')) {
          assignedRole = 'AUDITOR';
          name = 'Auditeur Externe';
        }

        const mockUser: User = {
          id: `usr-${Date.now()}`,
          name,
          email,
          role: assignedRole,
          avatar: name.split(' ').map(n => n[0]).join('')
        };

        const mockToken = `jwt_mock_token_for_${assignedRole}_${Date.now()}`;
        
        localStorage.setItem('siem_jwt_token', mockToken);
        localStorage.setItem('siem_authenticated', 'true');
        localStorage.setItem('siem_role', assignedRole);
        localStorage.setItem('siem_email', email);

        return { token: mockToken, user: mockUser };
      }
    );
  }

  async logout(): Promise<{ success: boolean }> {
    return this.request(
      'POST',
      '/auth/logout',
      null,
      () => {
        localStorage.removeItem('siem_jwt_token');
        localStorage.removeItem('siem_authenticated');
        localStorage.removeItem('siem_role');
        localStorage.removeItem('siem_email');
        return { success: true };
      }
    );
  }

  async getProfile(): Promise<User> {
    return this.request(
      'GET',
      '/auth/profile',
      null,
      () => {
        const email = localStorage.getItem('siem_email') || 'jean.dupont@smart-siem.com';
        const role = (localStorage.getItem('siem_role') as UserRole) || 'SOC_ANALYST';
        const name = role === 'ADMIN' ? 'Pierre Durand' : role === 'RSSI' ? 'Marc Lemaire' : role === 'AUDITOR' ? 'Auditeur Externe' : 'Jean Dupont';
        return {
          id: 'usr-current',
          name,
          email,
          role,
          avatar: name.split(' ').map(n => n[0]).join('')
        };
      }
    );
  }
}