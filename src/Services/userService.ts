// src/Services/userService.ts
import { BaseService } from './baseService';
import type { User, UserRole } from '../types';

const MOCK_USERS: User[] = [
  { id: 'user-1', name: 'Jean Dupont', email: 'jean.dupont@smart-siem.com', role: 'SOC_ANALYST', avatar: 'JD' },
  { id: 'user-2', name: 'Pierre Durand', email: 'pierre.durand@smart-siem.com', role: 'ADMIN', avatar: 'PD' },
  { id: 'user-3', name: 'Marc Lemaire', email: 'marc.lemaire@smart-siem.com', role: 'RSSI', avatar: 'ML' },
  { id: 'user-4', name: 'Auditeur Externe', email: 'auditor@smart-siem.com', role: 'AUDITOR', avatar: 'AE' }
];

export class UserService extends BaseService {
  private users = [...MOCK_USERS];
  private auditLogs: any[] = [];

  async getUsers(): Promise<User[]> {
    return this.request('GET', '/users', null, () => this.users);
  }

  async createUser(user: Omit<User, 'id'>): Promise<User> {
    return this.request(
      'POST',
      '/users',
      user,
      () => {
        const newUser: User = {
          ...user,
          id: `usr-${Date.now()}`
        };
        this.users = [...this.users, newUser];
        this.auditLogs = this.addAuditLog(this.auditLogs, 'Système', 'ADMIN', 'CREATE_USER', `Création utilisateur: ${newUser.name}`, 'SUCCESS');
        return newUser;
      }
    );
  }
}