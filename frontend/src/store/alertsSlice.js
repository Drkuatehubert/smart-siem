import { createSlice } from "@reduxjs/toolkit";
const s = createSlice({ name:"alerts", initialState:{list:[],total:0,loading:false},
  reducers:{ setAlerts:(st,a)=>{st.list=a.payload.results;st.total=a.payload.total;}, setLoading:(st,a)=>{st.loading=a.payload;} }
});
export const { setAlerts, setLoading } = s.actions; export default s.reducer;
