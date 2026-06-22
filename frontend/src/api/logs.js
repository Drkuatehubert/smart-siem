import api from "./axios"; export const searchLogs=(q)=>api.post("/logs/search",q); export const flagLog=(id,f)=>api.patch(`/logs/${id}/flag?flagged=${f}`);
