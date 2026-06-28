// src/Services/playbookService.ts
import { BaseService } from './baseService';
import type { SOARPlaybook, UserRole } from '../types';

const MOCK_PLAYBOOKS: SOARPlaybook[] = [
  {
    id: 'play-1',
    name: 'EDR Host Isolation',
    description: 'Isole automatiquement un hôte du réseau via l\'agent EDR.',
    trigger_event: 'Détection d\'un malware à haut niveau de confiance',
    steps: [
      'Valider la confiance de la signature de l\'alerte',
      'Requêter l\'agent EDR pour isoler l\'hôte',
      'Créer automatiquement un ticket de remédiation',
      'Notifier l\'équipe d\'astreinte SOC',
      'Sauvegarder l\'image mémoire vive pour analyse'
    ],
    is_active: true,
    last_triggered: '2026-06-27T19:15:30Z',
    executions_count: 14
  },
  {
    id: 'play-2',
    name: 'SSH Brute Force Block',
    description: 'Bloque l\'IP attaquante au niveau du pare-feu Cloud.',
    trigger_event: 'Règle de corrélation de Brute Force SSH activée',
    steps: [
      'Extraire l\'adresse IP source de l\'alerte',
      'Vérifier que l\'IP n\'appartient pas à un sous-réseau interne',
      'Déployer une règle de pare-feu de blocage',
      'Ajouter l\'IP dans l\'index interne des IoC'
    ],
    is_active: true,
    last_triggered: '2026-06-27T19:14:00Z',
    executions_count: 124
  },
  {
    id: 'play-3',
    name: 'Suspicious Domain DNS Block',
    description: 'Ajoute un domaine identifié au DNS menteur de l\'entreprise.',
    trigger_event: 'Clic Phishing détecté',
    steps: [
      'Extraire le nom de domaine de la requête',
      'Envoyer une mise à jour au serveur DNS interne',
      'Récupérer les hôtes ayant résolu ce domaine',
      'Déclencher un scan anti-malware'
    ],
    is_active: true,
    last_triggered: null,
    executions_count: 5
  }
];

export class PlaybookService extends BaseService {
  private playbooks = [...MOCK_PLAYBOOKS];
  private auditLogs: any[] = [];

  async getPlaybooks(): Promise<SOARPlaybook[]> {
    return this.request('GET', '/playbooks', null, () => this.playbooks);
  }

  async triggerPlaybook(id: string, user: string, role: UserRole): Promise<SOARPlaybook> {
    return this.request(
      'POST',
      `/playbooks/${id}/trigger`,
      { user, role },
      () => {
        this.playbooks = this.playbooks.map((p) => {
          if (p.id === id) {
            const updated = {
              ...p,
              last_triggered: new Date().toISOString(),
              executions_count: p.executions_count + 1
            };
            this.auditLogs = this.addAuditLog(this.auditLogs, user, role, 'TRIGGER_PLAYBOOK', `Triggered SOAR: ${p.name}`, 'SUCCESS');
            return updated;
          }
          return p;
        });
        const updatedPlay = this.playbooks.find((p) => p.id === id);
        if (!updatedPlay) throw new Error('Playbook non trouvé');
        return updatedPlay;
      }
    );
  }
}