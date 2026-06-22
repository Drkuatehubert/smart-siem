import { useEffect, useState } from "react";
import { getDashboard } from "../api/dashboard";
export default function DashboardAnalyst() {
  const [data, setData] = useState(null);
  useEffect(() => { getDashboard().then(r => setData(r.data)); }, []);
  if (!data) return <div style={{padding:"2rem",color:"var(--color-muted)"}}>Chargement...</div>;
  return (
    <div style={{padding:"2rem"}}>
      <h1 style={{color:"var(--color-primary)",marginBottom:"1.5rem"}}>Dashboard Analyste SOC</h1>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:"1rem"}}>
        <StatCard label="Alertes ouvertes" value={data.total_alerts_open} color="var(--color-warning)" />
        <StatCard label="Logs 24h" value={data.total_logs_24h} color="var(--color-primary)" />
      </div>
    </div>
  );
}
function StatCard({label,value,color}) {
  return <div style={{background:"var(--color-surface)",border:"1px solid var(--color-border)",borderRadius:"var(--radius)",padding:"1.5rem",borderLeft:`4px solid ${color}`}}>
    <p style={{color:"var(--color-muted)",fontSize:"0.875rem"}}>{label}</p>
    <p style={{fontSize:"2rem",fontWeight:"bold",color}}>{value}</p>
  </div>;
}
