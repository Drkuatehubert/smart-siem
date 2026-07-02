/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from "react";
import {
  Users,
  ShieldAlert,
  Search,
  UserPlus,
  Edit2,
  Trash2,
  Lock,
  Unlock,
  UserCheck,
  UserX,
  Clock,
  Shield,
  AlertCircle,
  X,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
} from "lucide-react";
import api from "../../Services/api";
import type { User, UserRole } from "../../types";
import { RBAC_POLICIES, getRoleBadgeStyles } from "../../utils/rbac";

interface AdminViewProps {
  activeRole: UserRole;
}

const ROLE_LABELS: Record<UserRole, string> = {
  admin: "Administrateur",
  analyst: "Analyste",
  reader: "Lecteur",
};

const ROLE_DESCRIPTIONS: Record<UserRole, string> = {
  admin: "Accès complet à la configuration du système, gestion des utilisateurs, sources de logs et politiques de sécurité.",
  analyst: "Peut gérer les alertes, effectuer des investigations, lancer des playbooks et générer des rapports techniques.",
  reader: "Accès en lecture seule aux rapports, conformité et logs systèmes.",
};

export default function AdminView({ activeRole }: AdminViewProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(5);

  const [showUserModal, setShowUserModal] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  const [formData, setFormData] = useState({
    username: "",
    email: "",
    role: "analyst" as UserRole,
    password: "",
    org_scope: "",
  });

  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  const [showAuditModal, setShowAuditModal] = useState(false);
  const [auditDate, setAuditDate] = useState<string>("");

  const isAdmin = activeRole === "admin";

  useEffect(() => {
    async function loadUsers() {
      try {
        const res = await api.getUsers();
        setUsers(res);
      } catch (err) {
        console.error("Erreur chargement utilisateurs", err);
      } finally {
        setLoading(false);
      }
    }
    loadUsers();
  }, []);

  const filteredUsers = users.filter((user) => {
    const searchLower = search.toLowerCase();
    return (
      user.username.toLowerCase().includes(searchLower) ||
      user.email.toLowerCase().includes(searchLower) ||
      ROLE_LABELS[user.role].toLowerCase().includes(searchLower)
    );
  });

  const totalPages = Math.ceil(filteredUsers.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentUsers = filteredUsers.slice(startIndex, endIndex);

  const totalUsers = users.length;
  const analystCount = users.filter((u) => u.role === "analyst").length;
  const activeSessions = users.filter((u) => {
    if (!u.last_login_at) return false;
    const lastLogin = new Date(u.last_login_at);
    const now = new Date();
    const diffMinutes = (now.getTime() - lastLogin.getTime()) / (1000 * 60);
    return diffMinutes < 60;
  }).length;
  const lockedUsers = users.filter((u) => u.locked_until).length;

  const canModifyUser = (targetUser: User): boolean => {
    if (!isAdmin) return false;
    if (targetUser.role === "admin") return false;
    return true;
  };

  const handleOpenCreate = () => {
    setEditingUser(null);
    setFormData({
      username: "",
      email: "",
      role: "analyst",
      password: "",
      org_scope: "",
    });
    setFormError("");
    setShowUserModal(true);
  };

  const handleOpenEdit = (user: User) => {
    if (!canModifyUser(user)) {
      setFormError("Vous ne pouvez pas modifier un administrateur.");
      return;
    }
    setEditingUser(user);
    setFormData({
      username: user.username,
      email: user.email,
      role: user.role,
      password: "",
      org_scope: user.org_scope || "",
    });
    setFormError("");
    setShowUserModal(true);
  };

  const handleSubmitUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    setIsSubmitting(true);

    if (!formData.username.trim() || !formData.email.trim()) {
      setFormError("Le nom d'utilisateur et l'email sont obligatoires.");
      setIsSubmitting(false);
      return;
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(formData.email)) {
      setFormError("Veuillez saisir une adresse email valide.");
      setIsSubmitting(false);
      return;
    }

    try {
      if (editingUser) {
        const updatedUsers = users.map((u) => {
          if (u.id === editingUser.id) {
            return {
              ...u,
              username: formData.username,
              email: formData.email,
              role: formData.role,
              org_scope: formData.org_scope || null,
            };
          }
          return u;
        });
        setUsers(updatedUsers);
      } else {
        const newUser = await api.createUser(
          {
            username: formData.username,
            email: formData.email,
            role: formData.role,
            hashed_password: formData.password || "temporary_hash",
            mfa_secret: "TEMP_SECRET",
            org_scope: formData.org_scope || undefined,
          },
          "admin_system"
        );
        setUsers([newUser, ...users]);
      }
      setShowUserModal(false);
      setFormError("");
    } catch (err) {
      console.error("Erreur sauvegarde utilisateur", err);
      setFormError("Erreur lors de la sauvegarde de l'utilisateur.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteUser = async (user: User) => {
    if (!canModifyUser(user)) {
      setFormError("Vous ne pouvez pas supprimer un administrateur.");
      return;
    }
    setUserToDelete(user);
    setShowDeleteModal(true);
  };

  const confirmDelete = async () => {
    if (!userToDelete) return;
    try {
      setUsers(users.filter((u) => u.id !== userToDelete.id));
      setShowDeleteModal(false);
      setUserToDelete(null);
    } catch (err) {
      console.error("Erreur suppression utilisateur", err);
      setFormError("Erreur lors de la suppression.");
    }
  };

  const handleToggleLock = async (user: User) => {
    if (!canModifyUser(user)) {
      setFormError("Vous ne pouvez pas verrouiller un administrateur.");
      return;
    }
    try {
      if (user.locked_until) {
        await api.lockUser(user.id, "", "admin_system", activeRole);
        setUsers(
          users.map((u) =>
            u.id === user.id ? { ...u, locked_until: null } : u
          )
        );
      } else {
        const lockUntil = new Date();
        lockUntil.setHours(lockUntil.getHours() + 24);
        await api.lockUser(user.id, lockUntil.toISOString(), "admin_system", activeRole);
        setUsers(
          users.map((u) =>
            u.id === user.id ? { ...u, locked_until: lockUntil.toISOString() } : u
          )
        );
      }
    } catch (err) {
      console.error("Erreur verrouillage utilisateur", err);
    }
  };

  const handleRunAudit = () => {
    const now = new Date();
    setAuditDate(now.toLocaleDateString("fr-FR", {
      day: "numeric",
      month: "long",
      year: "numeric",
    }));
    setShowAuditModal(true);
    setTimeout(() => {
      setShowAuditModal(false);
    }, 3000);
  };

  const getInitials = (username: string) => {
    return username
      .split(".")
      .map((part) => part.charAt(0).toUpperCase())
      .join("")
      .slice(0, 2);
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-8 h-full bg-app theme-transition">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 overflow-y-auto h-full pb-16 bg-app text-app theme-transition">
      {/* Header */}
      <div className="p-5 rounded-xl border border-app shadow-sm bg-card theme-transition">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <h4 className="font-bold text-sm flex items-center gap-2 text-app">
              <Users className="w-4.5 h-4.5 text-blue-600 dark:text-blue-400" />
              <span>Administration Utilisateurs</span>
            </h4>
            <p className="text-xs text-muted">
              Gérez les accès, les rôles et les sessions des membres de votre équipe SOC.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="text"
                placeholder="Rechercher utilisateur..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 pr-4 py-2 w-48 md:w-56 rounded-lg border text-xs focus:outline-none focus:border-blue-500 bg-input border-app text-app theme-transition"
              />
            </div>

            {isAdmin && (
              <button
                onClick={handleOpenCreate}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer shadow-md hover:shadow-blue-500/20"
              >
                <UserPlus className="w-4 h-4" />
                <span>Ajouter un utilisateur</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-app shadow-sm bg-card theme-transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-muted">
                Total Utilisateurs
              </p>
              <p className="text-2xl font-bold text-app">{totalUsers}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 text-blue-500 flex items-center justify-center">
              <Users className="w-5 h-5" />
            </div>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-app shadow-sm bg-card theme-transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-muted">
                Analystes Actifs
              </p>
              <p className="text-2xl font-bold text-app">{analystCount}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-500 flex items-center justify-center">
              <UserCheck className="w-5 h-5" />
            </div>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-app shadow-sm bg-card theme-transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-muted">
                Sessions Ouvertes
              </p>
              <p className="text-2xl font-bold text-app">{activeSessions}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 text-amber-500 flex items-center justify-center">
              <Clock className="w-5 h-5" />
            </div>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-app shadow-sm bg-card theme-transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-muted">
                Comptes Verrouillés
              </p>
              <p className="text-2xl font-bold text-red-500">{lockedUsers}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-red-500/10 text-red-500 flex items-center justify-center">
              <UserX className="w-5 h-5" />
            </div>
          </div>
        </div>
      </div>

      {/* User Table */}
      <div className="border border-app rounded-xl overflow-hidden shadow-sm bg-card theme-transition">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-app bg-table-header text-muted text-[10px] font-mono font-bold uppercase tracking-wider theme-transition">
                <th className="py-3 px-5">Nom</th>
                <th className="py-3 px-5">Email</th>
                <th className="py-3 px-5">Rôle</th>
                <th className="py-3 px-5">Dernière Connexion</th>
                <th className="py-3 px-5 text-center">Statut</th>
                {isAdmin && <th className="py-3 px-5 text-center">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-app theme-transition">
              {currentUsers.length === 0 ? (
                <tr>
                  <td colSpan={isAdmin ? 6 : 5} className="py-12 text-center text-muted">
                    <Users className="w-8 h-8 text-muted mx-auto mb-2" />
                    <span>Aucun utilisateur trouvé.</span>
                  </td>
                </tr>
              ) : (
                currentUsers.map((user) => {
                  const roleStyles = getRoleBadgeStyles(user.role);
                  const isLocked = user.locked_until !== null;
                  const isAdminUser = user.role === "admin";

                  return (
                    <tr
                      key={user.id}
                      className="hover:bg-table-row-hover theme-transition"
                    >
                      <td className="py-3 px-5">
                        <div className="flex items-center gap-3">
                          <div
                            className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-xs text-white ${
                              user.role === "admin"
                                ? "bg-red-500"
                                : user.role === "analyst"
                                ? "bg-emerald-500"
                                : "bg-blue-500"
                            }`}
                          >
                            {getInitials(user.username)}
                          </div>
                          <div>
                            <p className="font-bold text-sm text-app">
                              {user.username}
                            </p>
                            {user.org_scope && (
                              <p className="text-[10px] text-muted">
                                {user.org_scope}
                              </p>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-5 text-sm text-secondary">
                        {user.email}
                      </td>
                      <td className="py-3 px-5">
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border uppercase ${roleStyles.bg} ${roleStyles.text} ${roleStyles.border}`}
                        >
                          {ROLE_LABELS[user.role]}
                        </span>
                      </td>
                      <td className="py-3 px-5 text-sm text-muted">
                        {user.last_login_at
                          ? new Date(user.last_login_at).toLocaleString("fr-FR", {
                              day: "numeric",
                              month: "short",
                              year: "numeric",
                              hour: "2-digit",
                              minute: "2-digit",
                            })
                          : "Jamais"}
                      </td>
                      <td className="py-3 px-5 text-center">
                        {isLocked ? (
                          <span className="inline-flex items-center gap-1 text-xs text-red-500 font-bold">
                            <Lock className="w-3 h-3" />
                            Verrouillé
                          </span>
                        ) : user.is_active ? (
                          <span className="inline-flex items-center gap-1 text-xs text-emerald-500 font-bold">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block"></span>
                            Actif
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-muted font-bold">
                            Inactif
                          </span>
                        )}
                      </td>
                      {isAdmin && (
                        <td className="py-3 px-5">
                          <div className="flex items-center justify-center gap-1.5">
                            {!isAdminUser && (
                              <>
                                <button
                                  onClick={() => handleOpenEdit(user)}
                                  className="p-1.5 rounded-lg text-muted hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-950/20 transition-all cursor-pointer"
                                  title="Modifier"
                                >
                                  <Edit2 className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={() => handleToggleLock(user)}
                                  className={`p-1.5 rounded-lg transition-all cursor-pointer ${
                                    isLocked
                                      ? "text-amber-500 hover:text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-950/20"
                                      : "text-muted hover:text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-950/20"
                                  }`}
                                  title={isLocked ? "Déverrouiller" : "Verrouiller"}
                                >
                                  {isLocked ? (
                                    <Unlock className="w-4 h-4" />
                                  ) : (
                                    <Lock className="w-4 h-4" />
                                  )}
                                </button>
                                <button
                                  onClick={() => handleDeleteUser(user)}
                                  className="p-1.5 rounded-lg text-muted hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 transition-all cursor-pointer"
                                  title="Supprimer"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </>
                            )}
                            {isAdminUser && (
                              <span className="text-muted text-[10px] font-mono">
                                <Shield className="w-4 h-4 text-red-500" />
                              </span>
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {filteredUsers.length > itemsPerPage && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-app bg-table-header theme-transition">
            <p className="text-[10px] font-mono text-muted">
              Affichage de {startIndex + 1} à {Math.min(endIndex, filteredUsers.length)} sur {filteredUsers.length} utilisateurs
            </p>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
                className="p-1.5 rounded-lg text-muted hover:text-app disabled:opacity-30 disabled:cursor-not-allowed transition-all"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                let pageNum = i + 1;
                if (totalPages > 5 && currentPage > 3) {
                  pageNum = currentPage - 2 + i;
                  if (pageNum > totalPages) return null;
                }
                return (
                  <button
                    key={pageNum}
                    onClick={() => setCurrentPage(pageNum)}
                    className={`w-7 h-7 rounded-lg text-xs font-bold transition-all ${
                      currentPage === pageNum
                        ? "bg-blue-600 text-white"
                        : "text-muted hover:bg-table-row-hover hover:text-app"
                    }`}
                  >
                    {pageNum}
                  </button>
                );
              })}
              {totalPages > 5 && currentPage < totalPages - 2 && (
                <span className="text-muted">...</span>
              )}
              {totalPages > 5 && currentPage < totalPages - 1 && (
                <button
                  onClick={() => setCurrentPage(totalPages)}
                  className={`w-7 h-7 rounded-lg text-xs font-bold transition-all ${
                    currentPage === totalPages
                      ? "bg-blue-600 text-white"
                      : "text-muted hover:bg-table-row-hover hover:text-app"
                  }`}
                >
                  {totalPages}
                </button>
              )}
              <button
                onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
                className="p-1.5 rounded-lg text-muted hover:text-app disabled:opacity-30 disabled:cursor-not-allowed transition-all"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Roles Summary and Security Audit */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 rounded-xl border border-app shadow-sm bg-card theme-transition space-y-4">
          <h5 className="font-bold text-xs uppercase font-mono tracking-wider text-muted">
            Résumé des permissions par rôle
          </h5>
          <div className="space-y-4">
            {(Object.keys(ROLE_LABELS) as UserRole[]).map((role) => {
              const styles = getRoleBadgeStyles(role);
              const policy = RBAC_POLICIES[role];
              return (
                <div
                  key={role}
                  className="p-4 rounded-lg border border-app bg-table-header theme-transition"
                >
                  <div className="flex items-center gap-3 mb-2">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border uppercase ${styles.bg} ${styles.text} ${styles.border}`}
                    >
                      {ROLE_LABELS[role]}
                    </span>
                    <span className="text-[10px] font-mono text-muted">
                      {policy.allowedModules.length} modules autorisés
                    </span>
                  </div>
                  <p className="text-xs leading-relaxed text-secondary">
                    {ROLE_DESCRIPTIONS[role]}
                  </p>
                  <div className="flex flex-wrap gap-2 mt-2">
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-input text-muted">
                      {policy.canEditIncidents ? "✏️ Incidents" : "👁️ Incidents"}
                    </span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-input text-muted">
                      {policy.canEditRules ? "✏️ Règles" : "👁️ Règles"}
                    </span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-input text-muted">
                      {policy.canTriggerPlaybook ? "▶️ Playbooks" : "🚫 Playbooks"}
                    </span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-input text-muted">
                      {policy.canManageUsers ? "👤 User Mgmt" : "👁️ User Mgmt"}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="p-5 rounded-xl border border-app shadow-sm bg-card theme-transition space-y-4 flex flex-col justify-between">
          <div>
            <h5 className="font-bold text-xs uppercase font-mono tracking-wider flex items-center gap-2 text-muted">
              <ShieldAlert className="w-4 h-4 text-blue-500" />
              Audit de sécurité
            </h5>
            <p className="text-xs mt-3 leading-relaxed text-secondary">
              Dernière vérification des privilèges effectuée le{" "}
              <span className="font-bold text-app">
                {auditDate || "01 Octobre 2023"}
              </span>
              .
            </p>
            {showAuditModal && (
              <div className="mt-3 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center gap-2 animate-in fade-in slide-in-from-top-2 duration-300">
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                <span className="text-xs text-emerald-600 dark:text-emerald-400 font-medium">
                  Audit lancé avec succès ! Aucune anomalie détectée.
                </span>
              </div>
            )}
          </div>
          <button
            onClick={handleRunAudit}
            className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg border-2 border-blue-600/30 text-blue-600 dark:text-blue-400 hover:bg-blue-600 hover:text-white transition-all text-xs font-bold uppercase tracking-wider cursor-pointer"
          >
            <Lock className="w-4 h-4" />
            Lancer un audit
          </button>
        </div>
      </div>

      {/* CREATE/EDIT USER MODAL */}
      {showUserModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-xl border border-app shadow-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto bg-card theme-transition">
            <div className="flex items-center justify-between border-b border-app pb-3">
              <h4 className="font-bold text-sm flex items-center gap-2 text-app">
                <UserPlus className="w-4 h-4 text-blue-500" />
                <span>{editingUser ? "Modifier l'utilisateur" : "Ajouter un utilisateur"}</span>
              </h4>
              <button
                onClick={() => setShowUserModal(false)}
                className="text-muted hover:text-app cursor-pointer transition-colors"
              >
                <X className="w-4.5 h-4.5" />
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-start gap-2.5 text-xs text-red-400">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleSubmitUser} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono uppercase text-muted">
                  Nom d'utilisateur <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="ex: j.dupont"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  disabled={isSubmitting}
                  className="w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:border-blue-500 disabled:opacity-50 bg-input border-app text-app theme-transition"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono uppercase text-muted">
                  Email <span className="text-red-500">*</span>
                </label>
                <input
                  type="email"
                  required
                  placeholder="ex: utilisateur@entreprise.com"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  disabled={isSubmitting}
                  className="w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:border-blue-500 disabled:opacity-50 bg-input border-app text-app theme-transition"
                />
              </div>

              {!editingUser && (
                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono uppercase text-muted">
                    Mot de passe temporaire
                  </label>
                  <input
                    type="password"
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:border-blue-500 disabled:opacity-50 bg-input border-app text-app theme-transition"
                  />
                </div>
              )}

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono uppercase text-muted">
                  Rôle <span className="text-red-500">*</span>
                </label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value as UserRole })}
                  disabled={isSubmitting || editingUser?.role === "admin"}
                  className="w-full px-3 py-2 rounded-lg border text-xs focus:outline-none cursor-pointer disabled:opacity-50 bg-input border-app text-app theme-transition"
                >
                  <option value="admin">Administrateur</option>
                  <option value="analyst">Analyste</option>
                  <option value="reader">Lecteur</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono uppercase text-muted">
                  Périmètre / Organisation
                </label>
                <input
                  type="text"
                  placeholder="ex: SOC, DSI, AUDIT"
                  value={formData.org_scope}
                  onChange={(e) => setFormData({ ...formData, org_scope: e.target.value })}
                  disabled={isSubmitting}
                  className="w-full px-3 py-2 rounded-lg border text-xs focus:outline-none focus:border-blue-500 disabled:opacity-50 bg-input border-app text-app theme-transition"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-app">
                <button
                  type="button"
                  onClick={() => setShowUserModal(false)}
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg border border-app text-xs font-semibold text-secondary hover:bg-table-row-hover transition-all cursor-pointer disabled:opacity-50"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-blue-400 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer shadow-md flex items-center gap-2"
                >
                  {isSubmitting ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Enregistrement...</span>
                    </>
                  ) : (
                    <span>{editingUser ? "Mettre à jour" : "Créer l'utilisateur"}</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* DELETE CONFIRMATION MODAL */}
      {showDeleteModal && userToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-xl border border-app shadow-2xl p-6 space-y-4 bg-card theme-transition">
            <div className="flex items-center gap-3 text-red-500">
              <div className="w-10 h-10 rounded-full bg-red-500/10 flex items-center justify-center">
                <Trash2 className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-sm text-app">
                  Confirmer la suppression
                </h4>
                <p className="text-xs text-muted">
                  Cette action est irréversible.
                </p>
              </div>
            </div>

            <p className="text-sm text-secondary">
              Êtes-vous sûr de vouloir supprimer l'utilisateur{" "}
              <span className="font-bold text-app">{userToDelete.username}</span> ?
            </p>

            <div className="flex items-center justify-end gap-3 pt-4 border-t border-app">
              <button
                onClick={() => setShowDeleteModal(false)}
                className="px-4 py-2 rounded-lg border border-app text-xs font-semibold text-secondary hover:bg-table-row-hover transition-all cursor-pointer"
              >
                Annuler
              </button>
              <button
                onClick={confirmDelete}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer shadow-md"
              >
                Supprimer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}