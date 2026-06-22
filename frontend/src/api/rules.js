import api from "./axios"; export const getRules=()=>api.get("/rules"); export const createRule=(d)=>api.post("/rules",d); export const deleteRule=(id)=>api.delete(`/rules/${id}`);
