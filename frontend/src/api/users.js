import api from "./axios"; export const getUsers=()=>api.get("/users"); export const createUser=(d)=>api.post("/users",d);
