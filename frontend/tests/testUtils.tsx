import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";

import { AuthProvider } from "../src/contexts/AuthContext";
import type { Me } from "../src/types/api";

export type Route = (url: string, init?: RequestInit) => { status?: number; body?: unknown } | undefined;

/** Install a fetch mock. Unmatched requests fail the test loudly. */
export function mockFetch(route: Route) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const result = route(url, init);
    if (!result) throw new Error(`Unmocked request: ${init?.method ?? "GET"} ${url}`);
    const status = result.status ?? 200;
    return new Response(JSON.stringify(result.body ?? {}), { status, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

export function makeUser(role: string, permissions: string[]): Me {
  return {
    id: 1, username: `${role}.user`, email: `${role}@corp.example`, full_name: `${role} user`, role,
    role_display_name: role, is_active: true, last_login_at: null, created_at: "2026-11-01T00:00:00Z", permissions,
  };
}

export const VIEWER = ["dashboard:read", "events:read", "alerts:read", "incidents:read", "rules:read", "reports:read", "notifications:read"];
export const ANALYST = [...VIEWER, "events:ingest", "events:export", "alerts:triage", "alerts:manage", "incidents:manage",
  "detection:run", "intel:lookup", "anomaly:run", "ai:use", "reports:generate"];
export const ADMIN = [...ANALYST, "rules:manage", "intel:manage", "audit:read", "users:manage", "settings:manage", "demo:manage"];

/** Routes for an already signed-in session (refresh succeeds, /auth/me returns the user). */
export function sessionRoutes(user: Me | null): Route {
  // The app only tries to restore a session when the non-secret marker cookie exists.
  document.cookie = user ? "sentinel_session=1; path=/" : "sentinel_session=; Max-Age=0; path=/";
  return (url) => {
    if (url.endsWith("/auth/refresh")) return user ? { body: { access_token: "t", expires_in: 900 } } : { status: 401, body: { error: { code: "unauthorized", message: "No active session" } } };
    if (url.endsWith("/auth/me")) return { body: user };
    if (url.includes("/notifications/unread-count")) return { body: { count: 2 } };
    if (url.endsWith("/auth/public-config")) return { body: { public_demo: true, registration_enabled: false } };
    return undefined;
  };
}

export function renderApp(ui: ReactElement, path = "/") {
  return render(<MemoryRouter initialEntries={[path]}><AuthProvider>{ui}</AuthProvider></MemoryRouter>);
}
