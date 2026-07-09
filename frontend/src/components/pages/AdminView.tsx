import React, { useCallback, useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  Download,
  KeyRound,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldOff,
  User,
  UserCog,
  Users,
  X,
} from "lucide-react";
import api from "../../Services/api";
import type { AuditLog } from "../../types";
import type { UserRole } from "../../types";
import { getRoleBadgeStyles } from "../../utils/rbac";

// ─── Types locaux ────────────────────────────────────────────────────────────

interface UserRow {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  failed_login_count: number;
  last_login_at: string | null;
}

interface ActivityData {
  score: number;
  level: string;
  logins_success: number;
  logins_failed: number;
  alerts_acknowledged: number;
  soar_actions: number;
  exports: number;
  activity_by_day: { day: string; count: number }[];
  recent_actions: { time: string; action: string; result: string; detail: string }[];
}

// ─── Constantes ──────────────────────────────────────────────────────────────

const DB_ROLES = ["reader", "analyst", "rssi", "auditor", "admin"] as const;
type DBRole = (typeof DB_ROLES)[number];

const ROLE_LABELS: Record<string, string> = {
  admin: "Administrateur",
  analyst: "Analyste",
  rssi: "RSSI",
  auditor: "Auditeur",
  reader: "Lecteur",
};

const AUDIT_ACTIONS = [
  "user_login",
  "user_logout",
  "user_created",
  "user_deleted",
  "role_changed",
  "password_changed",
  "mfa_enrolled",
  "alert_acknowledged",
  "alert_closed",
  "alert_escalated",
  "incident_created",
  "incident_assigned",
  "incident_resolved",
  "rule_created",
  "rule_modified",
  "rule_deleted",
  "rule_toggled",
  "playbook_executed",
  "log_exported",
  "report_generated",
  "config_changed",
  "api_key_created",
];

const PERIODS = [
  { label: "1 heure", hours: 1 },
  { label: "24 heures", hours: 24 },
  { label: "7 jours", hours: 168 },
  { label: "30 jours", hours: 720 },
];

// ─── Sous-composants ─────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: string }) {
  const styles = getRoleBadgeStyles((role as UserRole) ?? "reader");
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${styles.bg} ${styles.text} ${styles.border}`}
    >
      {ROLE_LABELS[role] ?? role}
    </span>
  );
}

function StatusDot({ active }: { active: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs font-medium ${active ? "text-emerald-600 dark:text-emerald-400" : "text-slate-400"}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${active ? "bg-emerald-500" : "bg-slate-400"}`}
      />
      {active ? "Actif" : "Inactif"}
    </span>
  );
}

function ScoreCircle({ score }: { score: number }) {
  const r = 42;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score > 50 ? "#ef4444" : score > 20 ? "#f97316" : "#22c55e";
  return (
    <svg width="110" height="110" viewBox="0 0 110 110">
      <circle
        cx="55"
        cy="55"
        r={r}
        fill="none"
        stroke="currentColor"
        strokeWidth="10"
        className="text-slate-200 dark:text-slate-700"
      />
      <circle
        cx="55"
        cy="55"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth="10"
        strokeDasharray={circ}
        strokeDashoffset={offset}
        transform="rotate(-90 55 55)"
        strokeLinecap="round"
      />
      <text x="55" y="51" textAnchor="middle" fontSize="22" fontWeight="bold" fill={color}>
        {score}
      </text>
      <text x="55" y="68" textAnchor="middle" fontSize="10" fill="#94a3b8">
        /100
      </text>
    </svg>
  );
}

// ─── Composant principal ─────────────────────────────────────────────────────

interface AdminViewProps {
  activeRole: UserRole;
}

export default function AdminView({ activeRole }: AdminViewProps) {
  const [activeTab, setActiveTab] = useState<"users" | "audit" | "profile">("users");

  // Toast
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);
  const showToast = (msg: string, type: "success" | "error" | "info" = "info") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 4000);
  };

  // ── Tab 1: Utilisateurs ───────────────────────────────────────────────────
  const [users, setUsers] = useState<UserRow[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [userSearch, setUserSearch] = useState("");
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState({
    username: "",
    email: "",
    password: "",
    role: "analyst" as DBRole,
    mfa_enabled: false,
  });
  const [createLoading, setCreateLoading] = useState(false);
  const [roleDropdown, setRoleDropdown] = useState<string | null>(null);
  const [resetModal, setResetModal] = useState<{ userId: string; username: string; tempPw: string } | null>(null);

  const loadUsers = useCallback(async () => {
    setUsersLoading(true);
    try {
      const data = await api.getUsers();
      setUsers(data as unknown as UserRow[]);
    } catch {
      showToast("Erreur chargement utilisateurs", "error");
    } finally {
      setUsersLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "users") loadUsers();
  }, [activeTab, loadUsers]);

  const filteredUsers = users.filter(
    (u) =>
      u.username.toLowerCase().includes(userSearch.toLowerCase()) ||
      (u.email?.toLowerCase() ?? "").includes(userSearch.toLowerCase()),
  );

  const handleCreateUser = async () => {
    if (!createForm.username || !createForm.email || createForm.password.length < 8) {
      showToast("Remplissez tous les champs (MDP ≥ 8 chars)", "error");
      return;
    }
    setCreateLoading(true);
    try {
      await api.createUser({
        username: createForm.username,
        email: createForm.email,
        password: createForm.password,
        role: createForm.role,
        mfa_enabled: createForm.mfa_enabled,
      });
      setShowCreate(false);
      setCreateForm({ username: "", email: "", password: "", role: "analyst", mfa_enabled: false });
      showToast(`Utilisateur "${createForm.username}" créé`, "success");
      await loadUsers();
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      showToast(
        status === 409 ? "Nom d'utilisateur ou email déjà pris" : "Erreur création",
        "error",
      );
    } finally {
      setCreateLoading(false);
    }
  };

  const handleRoleChange = async (userId: string, role: string) => {
    setActionLoading(userId + ":role");
    setRoleDropdown(null);
    try {
      await api.updateRole(userId, role);
      showToast("Rôle mis à jour", "success");
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, role } : u)));
    } catch {
      showToast("Erreur changement de rôle", "error");
    } finally {
      setActionLoading(null);
    }
  };

  const handleToggleActive = async (userId: string, currentActive: boolean) => {
    setActionLoading(userId + ":active");
    try {
      if (currentActive) {
        await api.disableUser(userId);
      } else {
        await api.enableUser(userId);
      }
      showToast(currentActive ? "Compte désactivé" : "Compte réactivé", "success");
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, is_active: !currentActive } : u)),
      );
    } catch {
      showToast("Erreur activation/désactivation", "error");
    } finally {
      setActionLoading(null);
    }
  };

  const handleResetPassword = async (userId: string, username: string) => {
    setActionLoading(userId + ":reset");
    try {
      const res = await api.resetPassword(userId);
      setResetModal({ userId, username, tempPw: res.temp_password });
    } catch {
      showToast("Erreur réinitialisation MDP", "error");
    } finally {
      setActionLoading(null);
    }
  };

  // ── Tab 2: Audit logs ─────────────────────────────────────────────────────
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditLoading, setAuditLoading] = useState(false);
  const [filterUser, setFilterUser] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterPeriod, setFilterPeriod] = useState<number | null>(null);

  const loadAuditLogs = useCallback(async () => {
    setAuditLoading(true);
    try {
      const from_date = filterPeriod
        ? new Date(Date.now() - filterPeriod * 3600_000).toISOString()
        : undefined;
      const res = await api.getAuditLogs({
        user_id: filterUser || undefined,
        action: filterAction || undefined,
        from_date,
        size: 100,
      });
      setAuditLogs(res.results);
      setAuditTotal(res.total);
    } catch {
      showToast("Erreur chargement logs", "error");
    } finally {
      setAuditLoading(false);
    }
  }, [filterUser, filterAction, filterPeriod]);

  useEffect(() => {
    if (activeTab === "audit") loadAuditLogs();
  }, [activeTab, loadAuditLogs]);

  // Charger les utilisateurs pour les selects de l'onglet audit
  useEffect(() => {
    if (activeTab === "audit" && users.length === 0) loadUsers();
  }, [activeTab, users.length, loadUsers]);

  const handleExportCSV = () => {
    const token = localStorage.getItem("siem_jwt_token");
    const base =
      (import.meta as unknown as { env: Record<string, string> }).env
        .VITE_API_URL ?? "http://localhost:8000/api/v1";
    const params = new URLSearchParams({ format: "csv", max_rows: "10000" });
    if (filterAction) params.set("action", filterAction);
    fetch(`${base}/audit/logs/export?${params}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.blob())
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch(() => showToast("Export CSV échoué", "error"));
  };

  const resultColor = (r: string) => {
    if (r === "success") return "text-emerald-600 dark:text-emerald-400";
    if (r === "denied") return "text-red-500";
    return "text-amber-500";
  };

  // ── Tab 3: Profil de risque ───────────────────────────────────────────────
  const [profileUserId, setProfileUserId] = useState("");
  const [activity, setActivity] = useState<ActivityData | null>(null);
  const [profileLoading, setProfileLoading] = useState(false);

  const loadProfile = useCallback(async () => {
    if (!profileUserId) return;
    setProfileLoading(true);
    try {
      const data = (await api.getUserActivity(profileUserId)) as unknown as ActivityData;
      setActivity(data);
    } catch {
      showToast("Erreur chargement profil", "error");
    } finally {
      setProfileLoading(false);
    }
  }, [profileUserId]);

  useEffect(() => {
    if (activeTab === "profile" && profileUserId) loadProfile();
  }, [activeTab, profileUserId, loadProfile]);

  useEffect(() => {
    if (activeTab === "profile" && !profileUserId && users.length > 0) {
      setProfileUserId(users[0].id);
    }
  }, [activeTab, users, profileUserId]);

  // Ensure users list is available on profile tab
  useEffect(() => {
    if (activeTab === "profile" && users.length === 0) loadUsers();
  }, [activeTab, users.length, loadUsers]);

  // ─── Render ───────────────────────────────────────────────────────────────

  const isReadonly = activeRole !== "admin";

  return (
    <div className="h-full flex flex-col overflow-hidden relative">
      {/* Toast */}
      {toast && (
        <div
          className={`absolute top-4 right-4 z-50 flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-lg text-sm font-medium border ${
            toast.type === "success"
              ? "bg-emerald-50 dark:bg-emerald-900/30 border-emerald-200 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300"
              : toast.type === "error"
                ? "bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-700 text-red-700 dark:text-red-300"
                : "bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-700 text-blue-700 dark:text-blue-300"
          }`}
        >
          {toast.type === "success" ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : toast.type === "error" ? (
            <AlertCircle className="w-4 h-4 shrink-0" />
          ) : null}
          {toast.msg}
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 px-6 pt-4 pb-0 border-b border-slate-200 dark:border-slate-800 shrink-0">
        {(
          [
            { id: "users", label: "Utilisateurs", icon: Users },
            { id: "audit", label: "Logs d'audit", icon: Shield },
            { id: "profile", label: "Profil de risque", icon: UserCog },
          ] as const
        ).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
              activeTab === id
                ? "border-blue-500 text-blue-600 dark:text-blue-400"
                : "border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">

        {/* ──────────── TAB UTILISATEURS ──────────── */}
        {activeTab === "users" && (
          <div className="space-y-4">
            {/* Header bar */}
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Rechercher..."
                    value={userSearch}
                    onChange={(e) => setUserSearch(e.target.value)}
                    className="pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500 w-52"
                  />
                </div>
                <span className="text-xs text-slate-400 font-mono">
                  {filteredUsers.length}/{users.length}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={loadUsers}
                  className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-blue-500 transition-colors"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
                {!isReadonly && (
                  <button
                    onClick={() => setShowCreate(true)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    Créer un compte
                  </button>
                )}
              </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: "Total", val: users.length, color: "text-blue-600" },
                { label: "Actifs", val: users.filter((u) => u.is_active).length, color: "text-emerald-600" },
                { label: "MFA activé", val: users.filter((u) => u.mfa_enabled).length, color: "text-purple-600" },
                { label: "Verrouillés", val: users.filter((u) => u.failed_login_count > 3).length, color: "text-red-500" },
              ].map((s) => (
                <div
                  key={s.label}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4"
                >
                  <p className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">
                    {s.label}
                  </p>
                  <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.val}</p>
                </div>
              ))}
            </div>

            {/* Table */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
              {usersLoading ? (
                <div className="flex items-center justify-center py-16 gap-2 text-slate-400">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Chargement...</span>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
                        {["Utilisateur", "Rôle", "Statut", "MFA", "Échecs", "Dernière conn.", "Actions"].map(
                          (h) => (
                            <th
                              key={h}
                              className="px-4 py-2.5 text-left font-semibold text-slate-500 dark:text-slate-400 text-[10px] uppercase tracking-wider"
                            >
                              {h}
                            </th>
                          ),
                        )}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {filteredUsers.map((u) => (
                        <tr
                          key={u.id}
                          className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
                        >
                          {/* Utilisateur */}
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2.5">
                              <div className="w-7 h-7 rounded-full bg-blue-500/10 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-400 font-bold text-[10px] uppercase shrink-0">
                                {u.username?.[0] ?? "?"}
                              </div>
                              <div>
                                <p className="font-semibold text-slate-800 dark:text-slate-200">
                                  {u.username}
                                </p>
                                <p className="text-slate-400 text-[10px]">{u.email}</p>
                              </div>
                            </div>
                          </td>

                          {/* Rôle */}
                          <td className="px-4 py-3">
                            {!isReadonly ? (
                              <div className="relative inline-block">
                                <button
                                  onClick={() =>
                                    setRoleDropdown(roleDropdown === u.id ? null : u.id)
                                  }
                                  className="flex items-center gap-1"
                                  disabled={!!actionLoading}
                                >
                                  <RoleBadge role={u.role} />
                                  <ChevronDown className="w-3 h-3 text-slate-400" />
                                </button>
                                {roleDropdown === u.id && (
                                  <div className="absolute z-20 mt-1 w-36 rounded-lg border bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-700 shadow-lg py-1">
                                    {DB_ROLES.map((r) => (
                                      <button
                                        key={r}
                                        onClick={() => handleRoleChange(u.id, r)}
                                        className="w-full px-3 py-1.5 text-left text-xs hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                                      >
                                        <RoleBadge role={r} />
                                      </button>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ) : (
                              <RoleBadge role={u.role} />
                            )}
                          </td>

                          {/* Statut */}
                          <td className="px-4 py-3">
                            <StatusDot active={u.is_active} />
                          </td>

                          {/* MFA */}
                          <td className="px-4 py-3">
                            <span
                              className={`text-[10px] font-mono font-semibold ${u.mfa_enabled ? "text-emerald-600" : "text-slate-400"}`}
                            >
                              {u.mfa_enabled ? "OUI" : "NON"}
                            </span>
                          </td>

                          {/* Échecs */}
                          <td className="px-4 py-3">
                            <span
                              className={`font-mono font-bold ${u.failed_login_count > 3 ? "text-red-500" : "text-slate-600 dark:text-slate-300"}`}
                            >
                              {u.failed_login_count}
                            </span>
                          </td>

                          {/* Dernière connexion */}
                          <td className="px-4 py-3 text-slate-400 font-mono text-[10px]">
                            {u.last_login_at
                              ? new Date(u.last_login_at).toLocaleString("fr-FR", {
                                  day: "2-digit",
                                  month: "2-digit",
                                  year: "2-digit",
                                  hour: "2-digit",
                                  minute: "2-digit",
                                })
                              : "—"}
                          </td>

                          {/* Actions */}
                          <td className="px-4 py-3">
                            {isReadonly ? (
                              <span className="text-slate-300 dark:text-slate-600 text-[10px]">—</span>
                            ) : (
                              <div className="flex items-center gap-1">
                                <button
                                  onClick={() => handleToggleActive(u.id, u.is_active)}
                                  disabled={!!actionLoading}
                                  title={u.is_active ? "Désactiver" : "Activer"}
                                  className={`p-1.5 rounded-md border transition-colors ${
                                    u.is_active
                                      ? "border-red-200 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20"
                                      : "border-emerald-200 text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-900/20"
                                  }`}
                                >
                                  {actionLoading === u.id + ":active" ? (
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                  ) : u.is_active ? (
                                    <ShieldOff className="w-3 h-3" />
                                  ) : (
                                    <Shield className="w-3 h-3" />
                                  )}
                                </button>

                                <button
                                  onClick={() => handleResetPassword(u.id, u.username)}
                                  disabled={!!actionLoading}
                                  title="Réinitialiser MDP"
                                  className="p-1.5 rounded-md border border-amber-200 text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-900/20 transition-colors"
                                >
                                  {actionLoading === u.id + ":reset" ? (
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                  ) : (
                                    <KeyRound className="w-3 h-3" />
                                  )}
                                </button>

                                <button
                                  onClick={() => {
                                    setProfileUserId(u.id);
                                    setActiveTab("profile");
                                  }}
                                  title="Voir profil de risque"
                                  className="p-1.5 rounded-md border border-slate-200 dark:border-slate-700 text-slate-500 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                                >
                                  <User className="w-3 h-3" />
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                      {filteredUsers.length === 0 && (
                        <tr>
                          <td
                            colSpan={7}
                            className="px-4 py-12 text-center text-slate-400 text-xs"
                          >
                            Aucun utilisateur trouvé
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ──────────── TAB AUDIT ──────────── */}
        {activeTab === "audit" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3">
              <select
                value={filterUser}
                onChange={(e) => setFilterUser(e.target.value)}
                className="text-xs px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">Tous les utilisateurs</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username}
                  </option>
                ))}
              </select>

              <select
                value={filterAction}
                onChange={(e) => setFilterAction(e.target.value)}
                className="text-xs px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">Toutes les actions</option>
                {AUDIT_ACTIONS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>

              <select
                value={filterPeriod ?? ""}
                onChange={(e) =>
                  setFilterPeriod(e.target.value ? Number(e.target.value) : null)
                }
                className="text-xs px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">Toutes les périodes</option>
                {PERIODS.map((p) => (
                  <option key={p.hours} value={p.hours}>
                    {p.label}
                  </option>
                ))}
              </select>

              <button
                onClick={loadAuditLogs}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
              >
                <RefreshCw className="w-3 h-3" />
                Filtrer
              </button>

              <button
                onClick={handleExportCSV}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors ml-auto"
              >
                <Download className="w-3 h-3" />
                Exporter CSV
              </button>
            </div>

            <p className="text-xs text-slate-400 font-mono">
              {auditLogs.length} entrées affichées · {auditTotal} total
            </p>

            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
              {auditLoading ? (
                <div className="flex items-center justify-center py-16 gap-2 text-slate-400">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Chargement...</span>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
                        {["Horodatage", "Utilisateur", "Action", "Détail", "IP", "Résultat"].map(
                          (h) => (
                            <th
                              key={h}
                              className="px-4 py-2.5 text-left font-semibold text-slate-500 dark:text-slate-400 text-[10px] uppercase tracking-wider"
                            >
                              {h}
                            </th>
                          ),
                        )}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {auditLogs.map((log) => {
                        const row = log as unknown as Record<string, unknown>;
                        return (
                          <tr
                            key={log.id}
                            className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
                          >
                            <td className="px-4 py-2.5 font-mono text-[10px] text-slate-400 whitespace-nowrap">
                              {log.performed_at
                                ? new Date(log.performed_at).toLocaleString("fr-FR", {
                                    day: "2-digit",
                                    month: "2-digit",
                                    hour: "2-digit",
                                    minute: "2-digit",
                                    second: "2-digit",
                                  })
                                : "—"}
                            </td>
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-2">
                                <span className="font-medium text-slate-800 dark:text-slate-200">
                                  {(row.username as string) || log.username_snapshot || "—"}
                                </span>
                                {row.role_snapshot && (
                                  <RoleBadge role={row.role_snapshot as string} />
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-2.5">
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                                {log.action}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-slate-400 text-[10px] max-w-[180px] truncate">
                              {[log.resource_type, log.resource_id].filter(Boolean).join(" · ") || "—"}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-[10px] text-slate-400">
                              {log.ip_address ?? "—"}
                            </td>
                            <td className="px-4 py-2.5">
                              <span
                                className={`font-mono text-[10px] font-semibold uppercase ${resultColor(log.result)}`}
                              >
                                {log.result}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                      {auditLogs.length === 0 && (
                        <tr>
                          <td
                            colSpan={6}
                            className="px-4 py-12 text-center text-slate-400 text-xs"
                          >
                            Aucun log trouvé
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ──────────── TAB PROFIL DE RISQUE ──────────── */}
        {activeTab === "profile" && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Utilisateur :
              </label>
              <select
                value={profileUserId}
                onChange={(e) => setProfileUserId(e.target.value)}
                className="text-xs px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="">— Sélectionner —</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username} ({u.role})
                  </option>
                ))}
              </select>
              <button
                onClick={loadProfile}
                disabled={!profileUserId || profileLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white transition-colors"
              >
                {profileLoading ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <RefreshCw className="w-3 h-3" />
                )}
                Analyser
              </button>
            </div>

            {profileLoading && (
              <div className="flex items-center justify-center py-16 gap-2 text-slate-400">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span className="text-sm">Calcul du profil...</span>
              </div>
            )}

            {activity && !profileLoading && (
              <div className="grid grid-cols-3 gap-4">
                {/* Score */}
                <div className="col-span-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col items-center justify-center gap-2">
                  <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                    Score de risque
                  </p>
                  <ScoreCircle score={activity.score} />
                  <span
                    className={`text-xs font-bold uppercase tracking-wider ${
                      activity.score > 50
                        ? "text-red-500"
                        : activity.score > 20
                          ? "text-amber-500"
                          : "text-emerald-600"
                    }`}
                  >
                    Niveau : {activity.level}
                  </span>
                </div>

                {/* Stats */}
                <div className="col-span-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5">
                  <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-3">
                    Statistiques (7 jours)
                  </p>
                  <div className="space-y-2.5">
                    {[
                      { label: "Connexions réussies", val: activity.logins_success, color: "text-emerald-600" },
                      { label: "Connexions échouées", val: activity.logins_failed, color: "text-red-500" },
                      { label: "Alertes triées", val: activity.alerts_acknowledged, color: "text-blue-600" },
                      { label: "Actions SOAR", val: activity.soar_actions, color: "text-purple-600" },
                      { label: "Exports", val: activity.exports, color: "text-amber-600" },
                    ].map((s) => (
                      <div key={s.label} className="flex items-center justify-between">
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {s.label}
                        </span>
                        <span className={`text-sm font-bold font-mono ${s.color}`}>
                          {s.val}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* BarChart */}
                <div className="col-span-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5">
                  <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-3">
                    Activité par jour
                  </p>
                  {activity.activity_by_day.length > 0 ? (
                    <ResponsiveContainer width="100%" height={130}>
                      <BarChart
                        data={activity.activity_by_day}
                        margin={{ top: 0, right: 0, left: -20, bottom: 0 }}
                      >
                        <XAxis
                          dataKey="day"
                          tick={{ fontSize: 9, fill: "#94a3b8" }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <YAxis
                          tick={{ fontSize: 9, fill: "#94a3b8" }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{ fontSize: "10px", borderRadius: "8px", border: "1px solid #e2e8f0" }}
                        />
                        <Bar dataKey="count" fill="#3b82f6" radius={[3, 3, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className="text-xs text-slate-400 text-center py-8">Aucune activité</p>
                  )}
                </div>

                {/* Recent actions */}
                <div className="col-span-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                  <div className="px-5 py-3 border-b border-slate-100 dark:border-slate-800">
                    <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                      10 dernières actions
                    </p>
                  </div>
                  <div className="divide-y divide-slate-100 dark:divide-slate-800">
                    {activity.recent_actions.length === 0 && (
                      <p className="px-5 py-8 text-xs text-slate-400 text-center">
                        Aucune action récente
                      </p>
                    )}
                    {activity.recent_actions.map((a, i) => (
                      <div key={i} className="flex items-center gap-4 px-5 py-2.5">
                        <span className="font-mono text-[10px] text-slate-400 w-28 shrink-0">
                          {a.time
                            ? new Date(a.time).toLocaleString("fr-FR", {
                                day: "2-digit",
                                month: "2-digit",
                                hour: "2-digit",
                                minute: "2-digit",
                              })
                            : "—"}
                        </span>
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 shrink-0">
                          {a.action}
                        </span>
                        <span className="text-xs text-slate-400 flex-1 truncate">
                          {a.detail || "—"}
                        </span>
                        <span
                          className={`text-[10px] font-mono font-semibold uppercase shrink-0 ${resultColor(a.result)}`}
                        >
                          {a.result}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {!profileUserId && !profileLoading && (
              <div className="flex flex-col items-center justify-center py-24 gap-3 text-slate-400">
                <UserCog className="w-10 h-10 opacity-30" />
                <p className="text-sm">
                  Sélectionnez un utilisateur pour analyser son profil de risque
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Modal Création utilisateur ────────────────── */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl shadow-2xl w-full max-w-md mx-4 p-6">
            <div className="flex items-center justify-between mb-5">
              <h3 className="font-bold text-base text-slate-900 dark:text-slate-100">
                Créer un compte
              </h3>
              <button
                onClick={() => setShowCreate(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-3">
              {(
                [
                  { label: "Nom d'utilisateur", key: "username", type: "text", placeholder: "john.doe" },
                  { label: "Email", key: "email", type: "email", placeholder: "john@example.com" },
                  { label: "Mot de passe (≥ 8 chars)", key: "password", type: "password", placeholder: "••••••••" },
                ] as const
              ).map(({ label, key, type, placeholder }) => (
                <div key={key}>
                  <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">
                    {label}
                  </label>
                  <input
                    type={type}
                    placeholder={placeholder}
                    value={createForm[key] as string}
                    onChange={(e) =>
                      setCreateForm((f) => ({ ...f, [key]: e.target.value }))
                    }
                    className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              ))}

              <div>
                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">
                  Rôle
                </label>
                <select
                  value={createForm.role}
                  onChange={(e) =>
                    setCreateForm((f) => ({ ...f, role: e.target.value as DBRole }))
                  }
                  className="w-full px-3 py-2 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {DB_ROLES.map((r) => (
                    <option key={r} value={r}>
                      {ROLE_LABELS[r]}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="create_mfa"
                  checked={createForm.mfa_enabled}
                  onChange={(e) =>
                    setCreateForm((f) => ({ ...f, mfa_enabled: e.target.checked }))
                  }
                  className="w-3.5 h-3.5 rounded"
                />
                <label
                  htmlFor="create_mfa"
                  className="text-xs text-slate-600 dark:text-slate-400"
                >
                  Activer le MFA
                </label>
              </div>
            </div>

            <div className="flex items-center gap-2 mt-5">
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 px-4 py-2 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
              >
                Annuler
              </button>
              <button
                onClick={handleCreateUser}
                disabled={createLoading}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white transition-colors"
              >
                {createLoading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Créer le compte
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Modal Reset MDP ───────────────────────── */}
      {resetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl shadow-2xl w-full max-w-sm mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-base text-slate-900 dark:text-slate-100">
                Mot de passe réinitialisé
              </h3>
              <button
                onClick={() => setResetModal(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              MDP temporaire pour{" "}
              <span className="font-semibold text-slate-700 dark:text-slate-300">
                {resetModal.username}
              </span>{" "}
              (doit être changé à la prochaine connexion) :
            </p>
            <div className="flex items-center gap-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-3 mb-5">
              <Lock className="w-4 h-4 text-amber-500 shrink-0" />
              <code className="text-sm font-mono font-bold text-slate-800 dark:text-slate-200 flex-1 break-all">
                {resetModal.tempPw}
              </code>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(resetModal.tempPw);
                  showToast("MDP copié", "success");
                }}
                className="text-xs text-blue-500 hover:text-blue-600 font-semibold transition-colors"
              >
                Copier
              </button>
            </div>
            <button
              onClick={() => setResetModal(null)}
              className="w-full px-4 py-2 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
            >
              Fermer
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
