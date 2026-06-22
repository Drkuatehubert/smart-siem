import { createSlice } from "@reduxjs/toolkit";
const s = createSlice({ name: "auth", initialState: { token: localStorage.getItem("token"), user: null, role: null },
  reducers: { setAuth:(st,a)=>{ st.token=a.payload.token; st.user=a.payload.user; st.role=a.payload.user?.role; localStorage.setItem("token",a.payload.token); }, clearAuth:(st)=>{ st.token=null; st.user=null; st.role=null; localStorage.removeItem("token"); } }
});
export const { setAuth, clearAuth } = s.actions; export default s.reducer;
