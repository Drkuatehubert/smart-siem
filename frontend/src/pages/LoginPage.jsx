import { useState } from "react";
import { useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";
import { login } from "../api/auth";
import { setAuth } from "../store/authSlice";

export default function LoginPage() {
  const [username, setUsername] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  const dispatch = useDispatch(); const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault(); setError(""); setLoading(true);
    try {
      const { data } = await login(username, password);
      dispatch(setAuth({ token: data.access_token, user: data.user }));
      navigate("/dashboard");
    } catch { setError("Identifiants incorrects"); }
    finally { setLoading(false); }
  };

  return (
    <div style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:"100vh",background:"var(--color-bg)"}}>
      <div style={{background:"var(--color-surface)",padding:"2rem",borderRadius:"var(--radius)",width:"380px",border:"1px solid var(--color-border)"}}>
        <h1 style={{color:"var(--color-primary)",marginBottom:"1.5rem",textAlign:"center"}}>??? Smart SIEM</h1>
        <form onSubmit={handleSubmit}>
          <input id="username" value={username} onChange={e=>setUsername(e.target.value)} placeholder="Nom d utilisateur" required
            style={{width:"100%",padding:"0.75rem",marginBottom:"1rem",background:"var(--color-bg)",color:"var(--color-text)",border:"1px solid var(--color-border)",borderRadius:"var(--radius)"}} />
          <input id="password" type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Mot de passe" required
            style={{width:"100%",padding:"0.75rem",marginBottom:"1rem",background:"var(--color-bg)",color:"var(--color-text)",border:"1px solid var(--color-border)",borderRadius:"var(--radius)"}} />
          {error && <p style={{color:"var(--color-danger)",marginBottom:"1rem"}}>{error}</p>}
          <button type="submit" disabled={loading}
            style={{width:"100%",padding:"0.75rem",background:"var(--color-primary)",color:"#000",border:"none",borderRadius:"var(--radius)",cursor:"pointer",fontWeight:"bold"}}>
            {loading ? "Connexion..." : "Se connecter"}
          </button>
        </form>
      </div>
    </div>
  );
}
