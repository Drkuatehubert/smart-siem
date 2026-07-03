import axios from "axios";

const api = axios.create({ baseURL: "/api/v1" });

api.interceptors.request.use((cfg) => {
  const token = localStorage.getItem("siem_jwt_token");
  if (token) {
    cfg.headers = cfg.headers ?? {};
    cfg.headers.Authorization = `Bearer ${token}`;
  }
  return cfg;
});

api.interceptors.response.use(
  (r) => r,
  (e) => {
    if (e.response?.status === 401) {
      localStorage.removeItem("siem_jwt_token");
      localStorage.removeItem("siem_authenticated");
      localStorage.removeItem("siem_role");
      localStorage.removeItem("siem_email");
      window.location = "/login";
    }
    return Promise.reject(e);
  }
);

export default api;
