import React, { useState } from "react";
import {
  Shield,
  User,
  Lock,
  Eye,
  EyeOff,
  LogIn,
  Key,
  Fingerprint,
  QrCode,
  Sun,
  Moon,
  AlertCircle,
  ShieldCheck,
  RefreshCw,
  Smartphone,
} from "lucide-react";
import type { UserRole } from "../../types";
import { api } from "../../Services/api";

interface LoginViewProps {
  onLoginSuccess: (role: UserRole, email: string, keepSession: boolean) => void;
  isDarkMode: boolean;
  toggleTheme: () => void;
}

export default function LoginView({
  onLoginSuccess,
  isDarkMode,
  toggleTheme,
}: LoginViewProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [keepSession, setKeepSession] = useState(false);

  // Loading & Security verification states
  const [isLoading, setIsLoading] = useState(false);
  const [stepMessage, setStepMessage] = useState("");
  const [error, setError] = useState("");

  // Quick-fill credentials to make it easy to test different roles
  const quickProfiles = [
    {
      email: "jean.dupont@smart-siem.com",
      label: "Analyste SOC",
      role: "analyst" as UserRole,
    },
    {
      email: "pierre.durand@smart-siem.com",
      label: "Administrateur",
      role: "admin" as UserRole,
    },
    {
      email: "marc.lemaire@smart-siem.com",
      label: "RSSI",
      role: "reader" as UserRole,
    },
  ];

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!email) {
      setError("Veuillez saisir votre identifiant (adresse email).");
      return;
    }

    // Simple email validation
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      setError(
        "Veuillez saisir une adresse email valide (ex: nom.prenom@entreprise.com).",
      );
      return;
    }

    if (!password) {
      setError("Veuillez saisir votre mot de passe.");
      return;
    }

    if (password.length < 4) {
      setError("Le mot de passe doit contenir au moins 4 caractères.");
      return;
    }

    // Determine role based on email keyword or fallback to analyst
    let assignedRole: UserRole = "analyst";
    if (email.includes("admin") || email.includes("pierre")) {
      assignedRole = "admin";
    } else if (email.includes("rssi") || email.includes("marc")) {
      assignedRole = "reader";
    } else if (email.includes("audit") || email.includes("externe")) {
      assignedRole = "reader";
    }

    // Trigger sequential visual security steps to simulate real enterprise MFA SIEM login
    setIsLoading(true);

    const steps = [
      { msg: "Connexion au serveur d'authentification...", delay: 0 },
      { msg: "Vérification des identifiants chiffrés...", delay: 500 },
      { msg: "Vérification du code MFA TOTP...", delay: 1100 },
      { msg: "Poignée de main TLS sécurisée établie...", delay: 1600 },
      { msg: "Session sécurisée validée. Redirection...", delay: 2100 },
    ];

    steps.forEach((step) => {
      setTimeout(() => {
        setStepMessage(step.msg);
      }, step.delay);
    });

    // Make the REST API connection call via our central api service
    api
      .login(email, password, totpCode || undefined)
      .then((response) => {
        setTimeout(() => {
          onLoginSuccess(response.user.role, response.user.email, keepSession);
          setIsLoading(false);
        }, 2500);
      })
      .catch((err) => {
        setIsLoading(false);
        setError(
          err.message || "Échec de la connexion à la passerelle REST API.",
        );
      });
  };

  const handleQuickFill = (profile: (typeof quickProfiles)[0]) => {
    setEmail(profile.email);
    setPassword("•••••••••••••");
    setTotpCode("");
    setError("");
  };

  return (
    <div className="h-screen w-screen overflow-hidden relative bg-slate-950 text-slate-100 font-sans selection:bg-blue-500/30 selection:text-blue-200 flex flex-col items-center justify-center">
      {/* Deep Space Atmosphere Background */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl opacity-30 animate-pulse duration-5000"></div>
        <div className="absolute bottom-1/3 right-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl opacity-20 animate-pulse duration-7000"></div>
        {/* Subtle CSS star field simulation */}
        <div className="absolute inset-0 opacity-40 bg-[radial-gradient(#ffffff0a_1px,transparent_1px)] [background-size:16px_16px]"></div>
      </div>

      {/* Header Controls (Theme Toggle) - Positioned Absolutely at Top */}
      <header className="absolute top-0 left-0 right-0 w-full flex justify-end px-8 py-4 relative z-20 shrink-0">
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg border text-slate-400 dark:text-slate-300 bg-slate-900/40 border-slate-800 hover:bg-slate-800/60 hover:text-white hover:scale-105 active:scale-95 transition-all shadow-lg cursor-pointer"
          title="Basculer le thème"
        >
          {isDarkMode ? (
            <Sun className="w-4.5 h-4.5 text-amber-400" />
          ) : (
            <Moon className="w-4.5 h-4.5 text-slate-400" />
          )}
        </button>
      </header>

      {/* Center login form - Perfectly Centered Vertically and Horizontally */}
      <main className="w-full max-w-md px-6 flex flex-col justify-center items-center relative z-10 my-auto">
        {/* Logo and Branding Header */}
        <div className="flex flex-col items-center text-center mb-6 group cursor-default">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-600/20 to-emerald-500/20 border border-blue-500/30 flex items-center justify-center text-blue-400 shadow-2xl mb-4 p-0.5 transform group-hover:scale-110 group-hover:rotate-3 transition-all duration-300">
            <div className="w-full h-full rounded-xl bg-slate-950 flex items-center justify-center border border-blue-500/10">
              <Shield className="w-6 h-6 text-blue-500" />
            </div>
          </div>
          <h1 className="font-sans font-bold text-2xl text-white tracking-tight leading-none group-hover:text-blue-400 transition-colors duration-300">
            Smart SIEM
          </h1>
          <p className="text-xs text-slate-400 mt-2">
            Accédez à votre centre de sécurité opérationnel
          </p>
        </div>

        {/* Credentials Form Box */}
        <div className="w-full rounded-2xl border bg-slate-900/60 border-slate-800/80 backdrop-blur-md p-6 shadow-2xl space-y-5 hover:border-slate-700/80 transition-all duration-300">
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-start gap-2.5 text-xs text-red-400 animate-pulse">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {isLoading ? (
            /* Secure handshaking animated view */
            <div className="py-10 flex flex-col items-center justify-center text-center space-y-4">
              <div className="relative">
                <RefreshCw className="w-10 h-10 text-blue-500 animate-spin" />
                <ShieldCheck className="w-5 h-5 text-emerald-400 absolute top-2.5 left-2.5" />
              </div>
              <p className="text-xs font-mono text-emerald-400 tracking-wide font-semibold">
                {stepMessage}
              </p>
              <div className="w-48 h-1 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-blue-500 to-emerald-400 rounded-full animate-[loading-bar_2.5s_infinite]"></div>
              </div>
            </div>
          ) : (
            <form onSubmit={handleLogin} className="space-y-4">
              {/* Identifiant Field */}
              <div className="space-y-1.5 group">
                <label className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 group-hover:text-blue-400 transition-colors">
                  <User className="w-3.5 h-3.5" />
                  <span>Identifiant</span>
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="nom.prenom@entreprise.com"
                  className="w-full rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-950/80 px-3.5 py-2 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200 font-mono focus:shadow-[0_0_12px_rgba(59,130,246,0.15)]"
                />
              </div>

              {/* Password Field */}
              <div className="space-y-1.5 group">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 group-hover:text-blue-400 transition-colors">
                    <Lock className="w-3.5 h-3.5" />
                    <span>Mot de passe</span>
                  </label>
                  <a
                    href="#forgot"
                    onClick={(e) => {
                      e.preventDefault();
                      setError(
                        "Veuillez contacter votre administrateur SOC pour réinitialiser vos identifiants.",
                      );
                    }}
                    className="text-[11px] text-blue-400 hover:text-blue-300 hover:underline transition-all"
                  >
                    Mot de passe oublié ?
                  </a>
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-950/80 pl-3.5 pr-10 py-2 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200 font-mono focus:shadow-[0_0_12px_rgba(59,130,246,0.15)]"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                  >
                    {showPassword ? (
                      <EyeOff className="w-3.5 h-3.5" />
                    ) : (
                      <Eye className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>

              {/* TOTP Code Field */}
              <div className="space-y-1.5 group">
                <label className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 group-hover:text-blue-400 transition-colors">
                  <Smartphone className="w-3.5 h-3.5" />
                  <span>Code MFA (TOTP)</span>
                </label>
                <input
                  type="text"
                  value={totpCode}
                  onChange={(e) =>
                    setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                  }
                  placeholder="000000"
                  maxLength={6}
                  className="w-full rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-950/80 px-3.5 py-2 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200 font-mono tracking-[0.5em] text-center focus:shadow-[0_0_12px_rgba(59,130,246,0.15)]"
                />
              </div>

              {/* Keep session Checkbox */}
              <div className="flex items-center group">
                <input
                  type="checkbox"
                  id="keep-session"
                  checked={keepSession}
                  onChange={(e) => setKeepSession(e.target.checked)}
                  className="w-3.5 h-3.5 rounded border-slate-800 bg-slate-950 accent-blue-500 cursor-pointer focus:ring-0 focus:ring-offset-0 transition-transform group-hover:scale-105"
                />
                <label
                  htmlFor="keep-session"
                  className="ml-2 text-xs text-slate-400 group-hover:text-slate-200 transition-colors cursor-pointer select-none"
                >
                  Maintenir la session active
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg text-xs hover:scale-[1.02] active:scale-[0.98] transition-all duration-200 shadow-lg hover:shadow-[0_0_16px_rgba(59,130,246,0.4)] cursor-pointer"
              >
                <span>Se connecter</span>
                <LogIn className="w-4 h-4" />
              </button>
            </form>
          )}

          <div className="border-t border-slate-800/80 pt-4 flex flex-col items-center space-y-3">
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
              Authentification sécurisée par MFA
            </span>
            <div className="flex items-center gap-5 text-slate-600">
              <Key
                className="w-4 h-4 hover:text-blue-400 hover:scale-125 transition-all duration-200 cursor-pointer"
                aria-label="Clé FIDO2/WebAuthn"
              />
              <Fingerprint
                className="w-4 h-4 hover:text-blue-400 hover:scale-125 transition-all duration-200 cursor-pointer"
                aria-label="Données Biométriques"
              />
              <QrCode
                className="w-4 h-4 hover:text-blue-400 hover:scale-125 transition-all duration-200 cursor-pointer"
                aria-label="Code à usage unique"
              />
            </div>
          </div>
        </div>

        {/* Quick Simulation Credentials */}
        {!isLoading && (
          <div className="w-full mt-4 p-3 rounded-xl border border-slate-800/40 bg-slate-950/40 text-center space-y-2 hover:border-slate-800 transition-all duration-200">
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
              Accès de démonstration rapide (RBAC)
            </p>
            <div className="flex flex-wrap gap-1.5 justify-center">
              {quickProfiles.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => handleQuickFill(p)}
                  className="text-[9px] font-mono px-2 py-1 rounded bg-slate-900 border border-slate-800/80 text-slate-400 hover:text-blue-400 hover:border-blue-500 hover:bg-blue-500/10 hover:scale-105 active:scale-95 transition-all duration-200 cursor-pointer"
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Footer bar - Absolutely Positioned at Bottom */}
      <footer className="absolute bottom-0 left-0 right-0 w-full py-4 px-8 border-t border-slate-900 bg-slate-950/80 backdrop-blur flex flex-col md:flex-row gap-2 justify-between items-center z-20 text-[10px] font-mono text-slate-500">
        <div>
          v2.4.1 | Connexion aux logs :{" "}
          <span className="text-emerald-500 font-semibold">Active</span>
        </div>
        <div className="flex items-center gap-4">
          <a
            href="#status"
            onClick={(e) => {
              e.preventDefault();
              setError(
                "Tous les systèmes sont opérationnels (Uptime SIEM 99.99%).",
              );
            }}
            className="hover:text-slate-300 hover:underline transition-all cursor-pointer"
          >
            Statut Système
          </a>
          <a
            href="#support"
            onClick={(e) => {
              e.preventDefault();
              setError(
                "Contactez l'ingénieur de garde SOC au +33 1 42 27 00 00.",
              );
            }}
            className="hover:text-slate-300 hover:underline transition-all cursor-pointer"
          >
            Support Technique
          </a>
        </div>
      </footer>
    </div>
  );
}
