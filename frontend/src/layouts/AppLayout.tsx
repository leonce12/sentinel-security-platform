import {
  Bell, Bot, FileText, Globe, LayoutDashboard, ListTree, LogOut, Menu, ScrollText, Settings, Shield, ShieldAlert,
  Siren, SlidersHorizontal, UserCog, Users, X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";

import { cx } from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

// Each item is shown only if the user holds the permission. The backend still enforces it.
export const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: LayoutDashboard, perm: "dashboard:read" },
  { to: "/events", label: "Security Events", icon: ListTree, perm: "events:read" },
  { to: "/alerts", label: "Alerts", icon: ShieldAlert, perm: "alerts:read" },
  { to: "/incidents", label: "Incidents", icon: Siren, perm: "incidents:read" },
  { to: "/intel", label: "Threat Intelligence", icon: Globe, perm: "intel:lookup" },
  { to: "/rules", label: "Detection Rules", icon: SlidersHorizontal, perm: "rules:read" },
  { to: "/ai", label: "AI Security Analyst", icon: Bot, perm: "ai:use" },
  { to: "/reports", label: "Reports", icon: FileText, perm: "reports:read" },
  { to: "/notifications", label: "Notifications", icon: Bell, perm: "notifications:read" },
  { to: "/audit", label: "Audit Logs", icon: ScrollText, perm: "audit:read" },
  { to: "/users", label: "User Management", icon: Users, perm: "users:manage" },
  { to: "/settings", label: "Settings", icon: Settings, perm: "settings:manage" },
];

export function AppLayout() {
  const { user, logout, can } = useAuth();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const unread = useApi(() => api.get<{ count: number }>("/notifications/unread-count"), [location.pathname], { pollMs: 60_000 });

  useEffect(() => setOpen(false), [location.pathname]);

  const nav = (
    <nav className="flex flex-col gap-0.5 px-2" aria-label="Main">
      {NAV_ITEMS.filter((item) => can(item.perm)).map(({ to, label, icon: Icon }) => (
        <NavLink key={to} to={to} end={to === "/"}
          className={({ isActive }) => cx("flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
            isActive ? "bg-accent/10 text-accent" : "text-ink-muted hover:bg-surface-2 hover:text-ink")}>
          <Icon className="h-4 w-4 shrink-0" aria-hidden />
          <span className="flex-1">{label}</span>
          {to === "/notifications" && !!unread.data?.count && (
            <span className="rounded-full bg-accent-strong px-1.5 text-[11px] font-semibold text-white">{unread.data.count}</span>
          )}
        </NavLink>
      ))}
    </nav>
  );

  const brand = (
    <Link to="/" className="flex items-center gap-2 px-5 py-4">
      <Shield className="h-6 w-6 text-accent" aria-hidden />
      <span className="text-base font-semibold tracking-wide">Sentinel</span>
    </Link>
  );

  return (
    <div className="flex h-full">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-line bg-surface lg:flex">
        {brand}
        <div className="flex-1 overflow-y-auto pb-4">{nav}</div>
        <div className="border-t border-line px-4 py-3 text-xs text-ink-faint">Defensive monitoring platform</div>
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-black/60" />
          <aside className="absolute inset-y-0 left-0 w-64 overflow-y-auto border-r border-line bg-surface" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between pr-3">{brand}
              <button type="button" aria-label="Close menu" onClick={() => setOpen(false)} className="text-ink-muted"><X className="h-5 w-5" /></button>
            </div>
            {nav}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-surface/60 px-4">
          <button type="button" className="text-ink-muted lg:hidden" aria-label="Open menu" onClick={() => setOpen(true)}>
            <Menu className="h-5 w-5" />
          </button>
          <div className="flex-1" />
          {can("notifications:read") && (
            <Link to="/notifications" className="relative rounded-md p-2 text-ink-muted hover:bg-surface-2 hover:text-ink" aria-label="Notifications">
              <Bell className="h-4 w-4" />
              {!!unread.data?.count && <span className="absolute right-1 top-1 h-2 w-2 rounded-full bg-sev-critical" />}
            </Link>
          )}
          <Link to="/profile" className="flex items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-surface-2">
            <UserCog className="h-4 w-4 text-ink-muted" aria-hidden />
            <span className="hidden sm:inline">{user?.full_name || user?.username}</span>
            <span className="hidden rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-ink-muted md:inline">{user?.is_demo ? "Demo (read-only)" : user?.role_display_name}</span>
          </Link>
          <button type="button" onClick={logout} className="rounded-md p-2 text-ink-muted hover:bg-surface-2 hover:text-ink" aria-label="Sign out" title="Sign out">
            <LogOut className="h-4 w-4" />
          </button>
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6">
          <div className="mx-auto max-w-[1500px]"><Outlet /></div>
        </main>
      </div>
    </div>
  );
}
