import api from "./axios"; export const login=(u,p)=>api.post("/auth/login",{username:u,password:p}); export const me=()=>api.get("/auth/me"); export const logout=()=>api.post("/auth/logout");
