import { Navigate, Route, Routes, useLocation } from "react-router-dom";

import { Spinner } from "./components/ui";
import { useAuth } from "./contexts/AuthContext";
import { AppLayout } from "./layouts/AppLayout";
import AiAnalystPage from "./pages/AiAnalystPage";
import AlertDetailPage from "./pages/AlertDetailPage";
import AlertsPage from "./pages/AlertsPage";
import AuditPage from "./pages/AuditPage";
import DashboardPage from "./pages/DashboardPage";
import EventDetailPage from "./pages/EventDetailPage";
import EventsPage from "./pages/EventsPage";
import IncidentDetailPage from "./pages/IncidentDetailPage";
import IncidentsPage from "./pages/IncidentsPage";
import IntelPage from "./pages/IntelPage";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import NotificationsPage from "./pages/NotificationsPage";
import ProfilePage from "./pages/ProfilePage";
import ReportsPage from "./pages/ReportsPage";
import RulesPage from "./pages/RulesPage";
import SettingsPage from "./pages/SettingsPage";
import UsersPage from "./pages/UsersPage";

function RequirePermission({ perm, children }: { perm: string; children: JSX.Element }) {
  const { can } = useAuth();
  if (!can(perm)) {
    return (
      <div className="rounded-lg border border-line bg-surface p-8 text-center">
        <h1 className="text-lg font-semibold">Access denied</h1>
        <p className="mt-2 text-sm text-ink-muted">Your role does not include access to this page.</p>
      </div>
    );
  }
  return children;
}

export default function App() {
  const { user, ready } = useAuth();
  const location = useLocation();
  if (!ready) return <Spinner label="Starting Sentinel" />;
  if (!user) {
    return (
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace state={{ from: location.pathname }} />} />
      </Routes>
    );
  }
  const guard = (perm: string, element: JSX.Element) => <RequirePermission perm={perm}>{element}</RequirePermission>;
  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route element={<AppLayout />}>
        <Route index element={guard("dashboard:read", <DashboardPage />)} />
        <Route path="events" element={guard("events:read", <EventsPage />)} />
        <Route path="events/:id" element={guard("events:read", <EventDetailPage />)} />
        <Route path="alerts" element={guard("alerts:read", <AlertsPage />)} />
        <Route path="alerts/:id" element={guard("alerts:read", <AlertDetailPage />)} />
        <Route path="incidents" element={guard("incidents:read", <IncidentsPage />)} />
        <Route path="incidents/:id" element={guard("incidents:read", <IncidentDetailPage />)} />
        <Route path="intel" element={guard("intel:lookup", <IntelPage />)} />
        <Route path="rules" element={guard("rules:read", <RulesPage />)} />
        <Route path="ai" element={guard("ai:use", <AiAnalystPage />)} />
        <Route path="reports" element={guard("reports:read", <ReportsPage />)} />
        <Route path="notifications" element={guard("notifications:read", <NotificationsPage />)} />
        <Route path="audit" element={guard("audit:read", <AuditPage />)} />
        <Route path="users" element={guard("users:manage", <UsersPage />)} />
        <Route path="settings" element={guard("settings:manage", <SettingsPage />)} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="*" element={<div className="p-8 text-center text-ink-muted">Page not found.</div>} />
      </Route>
    </Routes>
  );
}
