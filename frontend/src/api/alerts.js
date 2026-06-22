import api from "./axios"; export const getAlerts=(p)=>api.get("/alerts",{params:p}); export const updateAlertStatus=(id,b)=>api.patch(`/alerts/${id}/status`,b);
