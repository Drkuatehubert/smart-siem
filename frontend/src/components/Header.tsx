/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from "react";
import {
  Sun,
  Moon,
  Bell,
  Shield,
  ChevronDown,
  Check,
  User,
  X,
  Trash2,
} from "lucide-react";
import type { UserRole } from "../types";
import { getRoleBadgeStyles, type ModuleID } from "../utils/rbac";
import api from "../Services/api";

interface HeaderProps {
  isDarkMode: boolean;
  toggleTheme: () => void;
  activeRole: UserRole;
  setActiveRole: (role: UserRole) => void;
  title: string;
  subtitle?: string;
  setActiveModule: (module: ModuleID) => void;
}

export default function Header({
  isDarkMode,
  toggleTheme,
  activeRole,
  setActiveRole,
  title,
  subtitle,
  setActiveModule,
}: HeaderProps) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showRoleSelector, setShowRoleSelector] = useState(false);

  // IDs of individually dismissed notifications (persisted)
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem("siem_dismissed_notifications");
      return new Set(stored ? (JSON.parse(stored) as string[]) : []);
    } catch {
      return new Set();
    }
  });

  // Timestamp of last "Effacer tout" (notifications older than this are hidden)
  const [clearedBefore, setClearedBefore] = useState<number>(() => {
    const ts = localStorage.getItem("siem_cleared_notifications");
    return ts ? parseInt(ts, 10) : 0;
  });

  const [notificationsList, setNotificationsList] = useState<
    {
      id: string;
      title: string;
      desc: string;
      time: string;
      triggeredMs: number;
      type: string;
      targetModule: ModuleID;
    }[]
  >([]);

  const fetchNotifications = useCallback(() => {
    api
      .getAlerts()
      .then((alerts) => {
        setNotificationsList((prev) => {
          const prevIds = new Set(prev.map((n) => n.id));
          const dismissed = JSON.parse(
            localStorage.getItem("siem_dismissed_notifications") || "[]"
          ) as string[];
          const dismissedSet = new Set(dismissed);
          const clearedTs = parseInt(
            localStorage.getItem("siem_cleared_notifications") || "0",
            10
          );

          const next = alerts
            .filter((alert) => {
              if (dismissedSet.has(alert.id)) return false;
              const ms = new Date(alert.triggered_at).getTime();
              if (ms <= clearedTs) return false;
              return true;
            })
            .slice(0, 8)
            .map((alert) => ({
              id: alert.id,
              title: alert.title,
              desc: `${alert.level.toUpperCase()} — ${alert.status}`,
              time: new Date(alert.triggered_at).toLocaleString("fr-FR"),
              triggeredMs: new Date(alert.triggered_at).getTime(),
              type: alert.level,
              targetModule: "alerts" as ModuleID,
            }));

          // Jouer un signal visuel uniquement si de nouvelles alertes apparaissent
          const hasNew = next.some((n) => !prevIds.has(n.id));
          if (hasNew && prevIds.size > 0) {
            // Forcer une mise à jour du badge (le state change suffit)
          }
          return next;
        });
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 30_000);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  const handleDismiss = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const next = new Set(dismissedIds);
    next.add(id);
    setDismissedIds(next);
    try {
      localStorage.setItem("siem_dismissed_notifications", JSON.stringify([...next]));
    } catch {}
    setNotificationsList((prev) => prev.filter((n) => n.id !== id));
  };

  const handleClearAll = () => {
    const now = Date.now();
    setClearedBefore(now);
    try {
      localStorage.setItem("siem_cleared_notifications", String(now));
    } catch {}
    setNotificationsList([]);
  };

  const rolesList: { id: UserRole; label: string; desc: string }[] = [
    {
      id: "analyst",
      label: "Analyste SOC",
      desc: "Analyse d'incidents, triage d'alertes, playbooks.",
    },
    {
      id: "admin",
      label: "Administrateur",
      desc: "Contrôle total, RBAC, sources, règles de corrélation.",
    },
    {
      id: "reader",
      label: "Lecteur",
      desc: "Vue rapports, conformité et logs systèmes uniquement.",
    },
  ];

  const roleStyles = getRoleBadgeStyles(activeRole);

  return (
    <header
      id="siem-header"
      className="h-16 border-b flex items-center justify-between px-8 bg-white dark:bg-[#0F172A] border-slate-200 dark:border-slate-800 transition-colors duration-300 shadow-sm shrink-0 relative z-40"
    >
      {/* Title */}
      <div id="header-title-container" className="flex items-center">
        <h2 className="font-bold text-base tracking-tight flex items-center">
          <span className="text-blue-600 dark:text-blue-400 font-bold text-lg">
            {title}
          </span>
          {subtitle && (
            <>
              <span className="mx-3 text-slate-300 dark:text-slate-700 font-light text-base select-none">
                |
              </span>
              <span className="text-slate-500 dark:text-slate-400 text-xs font-normal tracking-wide">
                {subtitle}
              </span>
            </>
          )}
        </h2>
      </div>

      {/* Top Controls */}
      <div id="header-controls" className="flex items-center gap-4">
        {/* Active Role Selector Trigger */}
        <div className="relative">
          <button
            onClick={() => {
              setShowRoleSelector(!showRoleSelector);
              setShowNotifications(false);
            }}
            id="role-selector-btn"
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all text-slate-700 dark:text-slate-300"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>Rôle Actif :</span>
            <span
              className={`px-2 py-0.5 rounded font-mono font-semibold text-[10px] uppercase border ${roleStyles.bg} ${roleStyles.text} ${roleStyles.border}`}
            >
              {activeRole}
            </span>
          </button>

          {showRoleSelector && (
            <div
              id="role-dropdown-menu"
              className="absolute right-0 mt-2 w-80 rounded-xl border bg-white dark:bg-[#0f1524] border-slate-200 dark:border-slate-800 shadow-xl py-2 text-slate-800 dark:text-slate-100 animate-in fade-in slide-in-from-top-3 duration-150"
            >
              <div className="px-4 py-2 border-b border-slate-100 dark:border-slate-800">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
                  Simuler un Profil RBAC
                </span>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Changez de rôle pour tester instantanément les restrictions
                  d'accès de la politique de sécurité.
                </p>
              </div>
              <div className="max-h-72 overflow-y-auto py-1">
                {rolesList.map((r) => {
                  const isSelected = activeRole === r.id;
                  const itemStyles = getRoleBadgeStyles(r.id);
                  return (
                    <button
                      key={r.id}
                      onClick={() => {
                        setActiveRole(r.id);
                        setShowRoleSelector(false);
                      }}
                      className="w-full flex items-start gap-3 px-4 py-2.5 hover:bg-slate-50 dark:hover:bg-slate-800/60 text-left transition-all group"
                    >
                      <div className="mt-0.5 shrink-0">
                        <div
                          className={`w-4 h-4 rounded-full border flex items-center justify-center ${isSelected ? "border-emerald-500 bg-emerald-500/10" : "border-slate-300 dark:border-slate-700"}`}
                        >
                          {isSelected && (
                            <Check className="w-2.5 h-2.5 text-emerald-500 stroke-[3]" />
                          )}
                        </div>
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-xs text-slate-900 dark:text-slate-100 group-hover:text-emerald-500 dark:group-hover:text-emerald-400 transition-colors">
                            {r.label}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded font-mono text-[9px] border ${itemStyles.bg} ${itemStyles.text} ${itemStyles.border}`}
                          >
                            {r.id}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 leading-snug">
                          {r.desc}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          id="theme-toggle-btn"
          className="p-2 rounded-lg border text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
          title="Basculer le thème"
        >
          {isDarkMode ? (
            <Sun className="w-4 h-4 text-amber-500" />
          ) : (
            <Moon className="w-4 h-4 text-slate-700" />
          )}
        </button>

        {/* Notifications Icon with Badge */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowRoleSelector(false);
            }}
            id="notifications-btn"
            className="p-2 rounded-lg border text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all relative"
          >
            <Bell className="w-4 h-4" />
            {notificationsList.length > 0 && (
              <span className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-red-500 text-white rounded-full text-[9px] font-bold flex items-center justify-center animate-pulse">
                {notificationsList.length}
              </span>
            )}
          </button>

          {showNotifications && (
            <div
              id="notifications-dropdown-menu"
              className="absolute right-0 mt-2 w-96 rounded-xl border bg-white dark:bg-[#0f1524] border-slate-200 dark:border-slate-800 shadow-xl py-2 text-slate-800 dark:text-slate-100 animate-in fade-in slide-in-from-top-3 duration-150"
            >
              {/* Header row */}
              <div className="px-4 py-2 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400">
                  Alertes de Sécurité Récentes
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-[9px] font-mono bg-red-500/10 text-red-500 border border-red-500/20 px-1.5 py-0.5 rounded">
                    {notificationsList.length} Actives
                  </span>
                  {notificationsList.length > 0 && (
                    <button
                      onClick={handleClearAll}
                      title="Effacer toutes les notifications"
                      className="flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-semibold text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all"
                    >
                      <Trash2 className="w-3 h-3" />
                      Effacer tout
                    </button>
                  )}
                </div>
              </div>

              {/* Notifications list */}
              <div className="divide-y divide-slate-100 dark:divide-slate-800/60 max-h-80 overflow-y-auto">
                {notificationsList.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-400 dark:text-slate-500">
                    Aucune notification active
                  </div>
                ) : (
                  notificationsList.map((n) => (
                    <div
                      key={n.id}
                      className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-all flex items-start gap-3 relative group"
                    >
                      <span
                        className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                          n.type === "critical"
                            ? "bg-red-500"
                            : n.type === "high"
                            ? "bg-amber-500"
                            : "bg-blue-500"
                        }`}
                      ></span>
                      <div
                        className="flex-1 cursor-pointer pr-6"
                        onClick={() => {
                          setActiveModule(n.targetModule);
                          setShowNotifications(false);
                        }}
                      >
                        <div className="flex items-center justify-between">
                          <h4 className="font-semibold text-xs text-slate-900 dark:text-slate-100 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                            {n.title}
                          </h4>
                          <span className="text-[9px] font-mono text-slate-400">
                            {n.time}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-snug">
                          {n.desc}
                        </p>
                      </div>

                      {/* Individual dismiss — persisted to localStorage */}
                      <button
                        onClick={(e) => handleDismiss(n.id, e)}
                        className="absolute right-3 top-4 p-1 rounded-md text-slate-400 hover:text-red-500 dark:hover:text-red-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all cursor-pointer opacity-0 group-hover:opacity-100"
                        title="Supprimer cette notification"
                        id={`dismiss-notification-${n.id}`}
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))
                )}
              </div>

              {/* Footer */}
              <div className="p-2 border-t border-slate-100 dark:border-slate-800 text-center">
                <button
                  onClick={() => setShowNotifications(false)}
                  className="w-full text-[10px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors font-mono cursor-pointer py-1 block text-center"
                >
                  Fermer
                </button>
              </div>
            </div>
          )}
        </div>

        {/* User Info Avatar */}
        <div
          id="header-user-badge"
          className="flex items-center gap-2.5 pl-2 border-l border-slate-200 dark:border-slate-800"
        >
          <div className="w-8 h-8 rounded-full bg-slate-200 dark:bg-slate-800 flex items-center justify-center text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 font-bold text-xs select-none uppercase">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden md:block">
            <h4 className="text-xs font-semibold text-slate-800 dark:text-slate-200">
              {localStorage.getItem('siem_username') || localStorage.getItem('siem_email') || activeRole}
            </h4>
            <p className="text-[9px] font-mono text-slate-400 tracking-wider uppercase">
              {activeRole}
            </p>
          </div>
        </div>
      </div>
    </header>
  );
}
