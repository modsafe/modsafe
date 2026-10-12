import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './stores/authStore';
import AdminLayout from './layouts/AdminLayout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import UserDetail from './pages/users/UserDetail';
import Organization from './pages/organization/Organization';
import ResourceList from './pages/resources/ResourceList';
import CcdRules from './pages/policies/CcdRules';
import Sessions from './pages/monitor/Sessions';
import Devices from './pages/devices/Devices';
import AuditAuthLogs from './pages/audit/AuditAuthLogs';
import AuditSessionLogs from './pages/audit/AuditSessionLogs';
import AuditAdminLogs from './pages/audit/AuditAdminLogs';
import AuthConfigPage from './pages/auth/AuthConfig';
import Certificates from './pages/certs/Certificates';
import TrafficBoard from './pages/monitor/TrafficBoard';
import NodeStatus from './pages/monitor/NodeStatus';
import FlowAudit from './pages/monitor/FlowAudit';
import Settings from './pages/settings/Settings';
import AlertCenter from './pages/alerts/AlertCenter';
import Enroll from './pages/Enroll';

function RequireAuth({ children }: { children: React.ReactElement }) {
  const token = useAuthStore((s) => s.token);
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/enroll"
          element={
            <RequireAuth>
              <Enroll />
            </RequireAuth>
          }
        />
        <Route
          path="/"
          element={
            <RequireAuth>
              <AdminLayout />
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          {/* 第一期 */}
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="organization" element={<Organization />} />
          <Route path="users/:id" element={<UserDetail />} />
          {/* 旧路径兼容重定向 */}
          <Route path="users" element={<Navigate to="/organization" replace />} />
          <Route path="groups" element={<Navigate to="/organization" replace />} />
          <Route path="resources" element={<ResourceList />} />
          <Route path="policies" element={<CcdRules />} />
          <Route path="monitor/sessions" element={<Sessions />} />
          {/* 第二期 */}
          <Route path="devices" element={<Devices />} />
          <Route path="audit/auth-logs" element={<AuditAuthLogs />} />
          <Route path="audit/session-logs" element={<AuditSessionLogs />} />
          <Route path="audit/admin-logs" element={<AuditAdminLogs />} />
          <Route path="auth/idp" element={<AuthConfigPage />} />
          <Route path="certificates" element={<Certificates />} />
          <Route path="alerts" element={<AlertCenter />} />
          <Route path="monitor/traffic" element={<TrafficBoard />} />
          <Route path="monitor/audit" element={<FlowAudit />} />
          <Route path="monitor/nodes" element={<NodeStatus />} />
          <Route path="settings/*" element={<Settings />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </HashRouter>
  );
}
