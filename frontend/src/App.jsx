import { Routes, Route, Navigate } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import DashboardAnalyst from "./pages/DashboardAnalyst";
import DashboardRSSI from "./pages/DashboardRSSI";
import AlertsPage from "./pages/AlertsPage";
import LogSearchPage from "./pages/LogSearchPage";
import AdminPage from "./pages/AdminPage";
import ProtectedRoute from "./components/common/ProtectedRoute";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/dashboard" element={<ProtectedRoute><DashboardAnalyst /></ProtectedRoute>} />
      <Route path="/dashboard/rssi" element={<ProtectedRoute roles={["administrateur","analyste"]}><DashboardRSSI /></ProtectedRoute>} />
      <Route path="/alerts" element={<ProtectedRoute><AlertsPage /></ProtectedRoute>} />
      <Route path="/logs" element={<ProtectedRoute><LogSearchPage /></ProtectedRoute>} />
      <Route path="/admin" element={<ProtectedRoute roles={["administrateur"]}><AdminPage /></ProtectedRoute>} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
