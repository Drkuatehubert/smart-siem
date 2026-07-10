// src/components/pages/RulesView.tsx
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from "react";
import {
  Shield,
  Plus,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Lock,
  X,
  Pencil,
} from "lucide-react";
import api from "../../Services/api";
import type {
  CorrelationRule,
  UserRole,
  RuleType,
  SeverityLevel,
} from "../../types";
import { RBAC_POLICIES } from "../../utils/rbac";

interface RulesViewProps {
  activeRole: UserRole;
}

export default function RulesView({ activeRole }: RulesViewProps) {
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  // Modal state — null = créer, rule = modifier
  const [showModal, setShowModal] = useState(false);
  const [editingRule, setEditingRule] = useState<CorrelationRule | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  // ✅ États du formulaire (nouveaux champs)
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [ruleType, setRuleType] = useState<RuleType>("threshold");
  const [conditions, setConditions] = useState("{\n  \n}");
  const [timeWindowSeconds, setTimeWindowSeconds] = useState("300");
  const [thresholdCount, setThresholdCount] = useState("5");
  const [alertLevel, setAlertLevel] = useState<SeverityLevel>("warning");
  const [confidenceScore, setConfidenceScore] = useState("75");
  const [mitreTactic, setMitreTactic] = useState("");
  const [mitreTechnique, setMitreTechnique] = useState("");
  const [playbookId, setPlaybookId] = useState("");

  const canEdit = RBAC_POLICIES[activeRole].canEditRules;

  useEffect(() => {
    async function loadRules() {
      try {
        const res = await api.getRules();
        setRules(res);
      } catch (err) {
        console.error("Erreur chargement règles de corrélation", err);
      } finally {
        setLoading(false);
      }
    }
    loadRules();
  }, []);

  const handleToggle = async (id: string) => {
    if (!canEdit) return;
    try {
      const updated = await api.toggleRule(id, "Dominique", activeRole);
      setRules((prev) => prev.map((r) => (r.id === id ? updated : r)));
    } catch (err) {
      console.error("Erreur bascule statut règle", err);
    }
  };

  const openEditModal = (rule: CorrelationRule) => {
    setEditingRule(rule);
    setName(rule.name);
    setDescription(rule.description || "");
    setRuleType(rule.rule_type);
    setConditions(JSON.stringify(rule.conditions, null, 2));
    setTimeWindowSeconds(rule.time_window_seconds?.toString() ?? "");
    setThresholdCount(rule.threshold_count?.toString() ?? "");
    setAlertLevel(rule.alert_level);
    setConfidenceScore(rule.confidence_score?.toString() ?? "75");
    setMitreTactic(rule.mitre_tactic ?? "");
    setMitreTechnique(rule.mitre_technique ?? "");
    setPlaybookId(rule.playbook_id ?? "");
    setFormError("");
    setShowModal(true);
  };

  const handleSubmitRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    setIsSubmitting(true);

    if (!name.trim()) {
      setFormError("Le nom de la règle est obligatoire.");
      setIsSubmitting(false);
      return;
    }

    let parsedConditions: Record<string, unknown>;
    try {
      parsedConditions = JSON.parse(conditions);
    } catch {
      setFormError("Les conditions doivent être un JSON valide.");
      setIsSubmitting(false);
      return;
    }

    try {
      if (editingRule) {
        // ── Mode édition ──────────────────────────────────────────────────────
        const updated = await api.updateRule(editingRule.id, {
          name: name.trim(),
          description: description.trim() || "Aucune description",
          rule_type: ruleType,
          conditions: parsedConditions,
          time_window_seconds: timeWindowSeconds ? parseInt(timeWindowSeconds, 10) : undefined,
          threshold_count:     thresholdCount    ? parseInt(thresholdCount, 10)    : undefined,
          alert_level:         alertLevel,
          confidence_score:    parseInt(confidenceScore, 10) || 0,
          mitre_tactic:        mitreTactic.trim()    || undefined,
          mitre_technique:     mitreTechnique.trim() || undefined,
        });
        setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      } else {
        // ── Mode création ─────────────────────────────────────────────────────
        const newRule = await api.addRule(
          {
            name: name.trim(),
            description: description.trim() || "Aucune description",
            rule_type: ruleType,
            conditions: parsedConditions,
            time_window_seconds: timeWindowSeconds ? parseInt(timeWindowSeconds, 10) : undefined,
            threshold_count:     thresholdCount    ? parseInt(thresholdCount, 10)    : undefined,
            alert_level:         alertLevel,
            confidence_score:    parseInt(confidenceScore, 10) || 0,
            mitre_tactic:        mitreTactic.trim()    || undefined,
            mitre_technique:     mitreTechnique.trim() || undefined,
            playbook_id:         playbookId.trim()     || undefined,
            is_active:           true,
          },
          "Dominique",
          activeRole,
        );
        setRules((prev) => [newRule, ...prev]);
      }

      resetForm();
      setEditingRule(null);
      setShowModal(false);
    } catch (err: unknown) {
      console.error("Erreur règle", err);
      setFormError(
        err instanceof Error ? err.message : "Erreur lors de l'enregistrement.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  // ✅ Fonction pour réinitialiser le formulaire
  const resetForm = () => {
    setName("");
    setDescription("");
    setRuleType("threshold");
    setConditions("{\n  \n}");
    setTimeWindowSeconds("300");
    setThresholdCount("5");
    setAlertLevel("warning");
    setConfidenceScore("75");
    setMitreTactic("");
    setMitreTechnique("");
    setPlaybookId("");
    setFormError("");
  };

  if (loading) {
    return (
      <div
        id="rules-loading"
        className="flex-1 flex items-center justify-center p-8 h-full"
      >
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const filteredRules = rules.filter((rule) => {
    const name = (rule.name || "").toLowerCase();
    const desc = (rule.description || "").toLowerCase();
    const q = search.toLowerCase();
    return name.includes(q) || desc.includes(q);
  });

  // Badge styles for rule_type
  const ruleTypeBadge = (rt: RuleType): string => {
    switch (rt) {
      case "threshold":
        return "text-blue-500 bg-blue-500/10 border-blue-500/20";
      case "pattern":
        return "text-purple-500 bg-purple-500/10 border-purple-500/20";
      case "behavioral":
        return "text-amber-500 bg-amber-500/10 border-amber-500/20";
      case "composite":
        return "text-rose-500 bg-rose-500/10 border-rose-500/20";
      case "cross_source":
        return "text-teal-500 bg-teal-500/10 border-teal-500/20";
      default:
        return "text-slate-500 bg-slate-500/10 border-slate-500/20";
    }
  };

  return (
    <div
      id="rules-view"
      className="p-6 space-y-6 overflow-y-auto h-full pb-16 relative"
    >
      {/* Search and Action Bar */}
      <div className="bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span>Moteur de Corrélation & Détection</span>
          </h4>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Configurez des règles d'alerte en continu sur les flux ElasticSearch
            indexés par le SIEM.
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher règle..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-4 py-2 w-52 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none"
            />
          </div>

          <button
            onClick={() => {
              resetForm();
              setShowModal(true);
            }}
            disabled={!canEdit}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-300 dark:disabled:bg-slate-800 text-white font-bold text-xs transition-all active:scale-95 cursor-pointer disabled:cursor-not-allowed shadow-md hover:shadow-blue-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>Créer une règle</span>
          </button>
        </div>
      </div>

      {/* Rules list */}
      <div className="space-y-4">
        {filteredRules.length === 0 ? (
          <div className="py-16 text-center text-slate-400">
            <Shield className="w-10 h-10 text-slate-300 dark:text-slate-700 mx-auto mb-3 animate-pulse" />
            <span>Aucune règle de corrélation configurée.</span>
          </div>
        ) : (
          filteredRules.map((rule) => {
            const sevColors =
              rule.alert_level === "critical"
                ? "text-red-500 bg-red-500/10 border-red-500/20"
                : rule.alert_level === "high"
                  ? "text-orange-500 bg-orange-500/10 border-orange-500/20"
                  : rule.alert_level === "warning"
                    ? "text-amber-500 bg-amber-500/10 border-amber-500/20"
                    : "text-blue-500 bg-blue-500/10 border-blue-500/20";

            return (
              <div
                key={rule.id}
                className={`bg-white dark:bg-[#1E293B] p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm transition-all relative overflow-hidden ${
                  !rule.is_active ? "opacity-70" : ""
                }`}
              >
                {/* Visual Status strip */}
                <div
                  className={`absolute left-0 inset-y-0 w-1 ${rule.is_active ? "bg-blue-500" : "bg-slate-300"}`}
                ></div>

                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] font-mono font-bold text-slate-400">
                        {rule.id}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border uppercase ${sevColors}`}
                      >
                        {rule.alert_level}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border uppercase ${ruleTypeBadge(rule.rule_type)}`}
                      >
                        {rule.rule_type}
                      </span>
                      <h5 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex-1 min-w-[200px]">
                        {rule.name}
                      </h5>
                    </div>

                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {rule.description}
                    </p>

                    {/* Conditions / MITRE / Confidence row */}
                    <div className="flex flex-wrap items-center gap-3 mt-2">
                      {rule.confidence_score > 0 && (
                        <span className="text-[10px] font-mono font-bold text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-900 px-2 py-0.5 rounded">
                          Score: {rule.confidence_score}/100
                        </span>
                      )}
                      {rule.mitre_tactic && (
                        <span className="text-[10px] font-mono font-bold text-purple-500 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded">
                          MITRE: {rule.mitre_tactic}
                          {rule.mitre_technique
                            ? ` / ${rule.mitre_technique}`
                            : ""}
                        </span>
                      )}
                      {rule.time_window_seconds && (
                        <span className="text-[10px] font-mono text-slate-400">
                          Fenêtre: {rule.time_window_seconds}s
                        </span>
                      )}
                      {rule.threshold_count && (
                        <span className="text-[10px] font-mono text-slate-400">
                          Seuil: {rule.threshold_count}
                        </span>
                      )}
                      {rule.playbook_id && (
                        <span className="text-[10px] font-mono text-blue-400">
                          Playbook: {rule.playbook_id}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Toggle controls */}
                  <div className="flex flex-row md:flex-col items-center justify-between md:justify-start gap-4 shrink-0 border-t md:border-t-0 border-slate-100 dark:border-slate-800/60 pt-3 md:pt-0">
                    <div className="flex items-center gap-1.5">
                      {rule.is_active ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <XCircle className="w-4 h-4 text-slate-400" />
                      )}
                      <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-450">
                        {rule.is_active ? "Actif" : "Désactivé"}
                      </span>
                    </div>

                    {canEdit ? (
                      <div className="flex gap-2">
                        <button
                          onClick={() => openEditModal(rule)}
                          className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer bg-blue-500/10 text-blue-500 border border-blue-500/20 hover:bg-blue-500 hover:text-white flex items-center gap-1"
                          title="Modifier la règle"
                        >
                          <Pencil className="w-3 h-3" />
                          Modifier
                        </button>
                        <button
                          onClick={() => handleToggle(rule.id)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                            rule.is_active
                              ? "bg-rose-500/10 text-rose-500 border border-rose-500/20 hover:bg-rose-500 hover:text-white"
                              : "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 hover:bg-emerald-500 hover:text-white"
                          }`}
                        >
                          {rule.is_active ? "Désactiver" : "Activer"}
                        </button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1 text-[10px] text-slate-400 font-bold uppercase font-mono bg-slate-100 dark:bg-slate-900 px-2 py-1 rounded">
                        <Lock className="w-3 h-3" />
                        <span>Lecture Seule</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/60 pt-3 mt-4 text-[10px] font-mono text-slate-400">
                  <span>Créé par: {rule.created_by}</span>
                  {rule.false_positive_count > 0 && (
                    <div className="flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>{rule.false_positive_count} faux positifs</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* ✅ CREATE RULE MODAL DIALOG - NOUVEAUX CHAMPS */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1E293B] w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 shadow-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/60 pb-3">
              <h4 className="font-bold text-sm text-slate-900 dark:text-slate-100 flex items-center gap-2">
                {editingRule ? (
                  <Pencil className="w-4 h-4 text-blue-500" />
                ) : (
                  <Shield className="w-4 h-4 text-blue-500" />
                )}
                <span>
                  {editingRule ? "Modifier la règle" : "Nouvelle règle de corrélation"}
                </span>
              </h4>
              <button
                onClick={() => {
                  setShowModal(false);
                  setEditingRule(null);
                  resetForm();
                  setFormError("");
                }}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4.5 h-4.5" />
              </button>
            </div>

            {/* ✅ Affichage des erreurs */}
            {formError && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-start gap-2.5 text-xs text-red-400">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleSubmitRule} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                  Nom de la règle <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="ex: Brute Force SSH détecté"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  disabled={isSubmitting}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                  Description
                </label>
                <textarea
                  placeholder="Expliquez la logique d'alerte..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  disabled={isSubmitting}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 h-20 resize-none disabled:opacity-50"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                    Type de règle <span className="text-red-500">*</span>
                  </label>
                  <select
                    value={ruleType}
                    onChange={(e) => setRuleType(e.target.value as RuleType)}
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none disabled:opacity-50"
                  >
                    <option value="threshold">Seuil (Threshold)</option>
                    <option value="pattern">Pattern</option>
                    <option value="behavioral">Comportemental</option>
                    <option value="composite">Composite</option>
                    <option value="cross_source">Multi-sources (Cross-source)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                    Niveau d'alerte <span className="text-red-500">*</span>
                  </label>
                  <select
                    value={alertLevel}
                    onChange={(e) =>
                      setAlertLevel(e.target.value as SeverityLevel)
                    }
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none disabled:opacity-50"
                  >
                    <option value="info">Info</option>
                    <option value="warning">Avertissement</option>
                    <option value="high">Haute</option>
                    <option value="critical">Critique</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                  Conditions (JSON) <span className="text-red-500">*</span>
                </label>
                <textarea
                  required
                  placeholder='ex: {"field": "event.action", "value": "auth_failure"}'
                  value={conditions}
                  onChange={(e) => setConditions(e.target.value)}
                  disabled={isSubmitting}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 h-24 font-mono resize-none disabled:opacity-50"
                />
                <p className="text-[9px] text-slate-400 font-mono">
                  Définissez les conditions de corrélation au format JSON
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                    Fenêtre (s)
                  </label>
                  <input
                    type="number"
                    min="0"
                    placeholder="300"
                    value={timeWindowSeconds}
                    onChange={(e) => setTimeWindowSeconds(e.target.value)}
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                    Seuil
                  </label>
                  <input
                    type="number"
                    min="0"
                    placeholder="5"
                    value={thresholdCount}
                    onChange={(e) => setThresholdCount(e.target.value)}
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                    Score conf.
                  </label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    placeholder="75"
                    value={confidenceScore}
                    onChange={(e) => setConfidenceScore(e.target.value)}
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                    MITRE Tactic
                  </label>
                  <input
                    type="text"
                    placeholder="ex: TA0006"
                    value={mitreTactic}
                    onChange={(e) => setMitreTactic(e.target.value)}
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                    MITRE Technique
                  </label>
                  <input
                    type="text"
                    placeholder="ex: T1110"
                    value={mitreTechnique}
                    onChange={(e) => setMitreTechnique(e.target.value)}
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold font-mono text-slate-450 uppercase">
                  Playbook associé (ID)
                </label>
                <input
                  type="text"
                  placeholder="ex: playbook-001"
                  value={playbookId}
                  onChange={(e) => setPlaybookId(e.target.value)}
                  disabled={isSubmitting}
                  className="w-full px-3 py-2 rounded-lg border text-xs bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100 dark:border-slate-800/60">
                <button
                  type="button"
                  onClick={() => {
                    setShowModal(false);
                    setEditingRule(null);
                    resetForm();
                    setFormError("");
                  }}
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all cursor-pointer disabled:opacity-50"
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
                    <span>{editingRule ? "Mettre à jour" : "Enregistrer la règle"}</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
