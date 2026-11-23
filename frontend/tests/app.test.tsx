import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "../src/App";
import { RiskScore, SeverityBadge } from "../src/components/ui";
import { setAccessToken } from "../src/services/api";
import { ADMIN, ANALYST, VIEWER, makeUser, mockFetch, renderApp, sessionRoutes } from "./testUtils";
import { render } from "@testing-library/react";

vi.mock("recharts", async () => {
  // Charts need real layout; in jsdom render simple placeholders instead.
  const Stub = ({ children }: { children?: unknown }) => <div data-testid="chart">{children as never}</div>;
  const Empty = () => null;
  return { ResponsiveContainer: Stub, AreaChart: Stub, BarChart: Stub, LineChart: Stub, Area: Empty, Bar: Empty, Line: Empty,
    CartesianGrid: Empty, Cell: Empty, Legend: Empty, Tooltip: Empty, XAxis: Empty, YAxis: Empty };
});

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

const SUMMARY = {
  range: { start: "2026-11-08T23:57:07Z", end: "2026-11-15T23:57:07Z" }, total_events: 6928, total_alerts: 16, open_alerts: 15,
  open_incidents: 1, critical_incidents: 1, high_risk_events: 27, events_requiring_investigation: 442, auth_failures: 49,
  synthetic_events: 6928, ingestion: { total_jobs: 2, failed_jobs_24h: 0, last_job: { id: 2, status: "completed", filename: "demo.json", created_at: "2026-11-22T21:00:00Z", processed: 177, rejected: 0, duplicates: 0 } },
};
const ANALYTICS = {
  range: { start: SUMMARY.range.start, end: SUMMARY.range.end, bucket: "hour" },
  events_over_time: [{ bucket: "2026-11-10T10:00:00Z", informational: 5, low: 1, medium: 0, high: 0, critical: 0, total: 6 }],
  auth_activity: [{ bucket: "2026-11-10T10:00:00Z", success: 4, failure: 2, other: 0 }],
  alerts_by_severity: [{ severity: "critical", count: 1 }], event_categories: [{ category: "authentication", count: 6 }],
  top_sources: [{ source: "vpn-gw-01", count: 6 }], incident_status: [{ status: "open", count: 1 }],
  risk_distribution: [{ band: "80-100", count: 1 }],
  rule_performance: [{ rule_id: "SEN-AUTH-001", name: "Repeated authentication failures", enabled: true, alerts: 2, false_positives: 0, open: 2, avg_score: 67 }],
};
const EVENTS = { items: [{ id: 7, event_uid: "E7", timestamp: "2026-11-10T10:00:00Z", source_system: "vpn-gw-01", source_ip: "203.0.113.45",
  destination_ip: null, username: "nora.b", event_category: "authentication", event_type: "login_failure", severity: "low", action: "login",
  outcome: "failure", resource: null, description: "Invalid password", risk_score: 62, is_synthetic: true, ingestion_job_id: 1, ingested_at: "2026-11-22T21:00:00Z" }],
  total: 1, page: 1, page_size: 10, pages: 1 };

function dashboardRoutes(user = makeUser("viewer", VIEWER)) {
  const session = sessionRoutes(user);
  return (url: string, init?: RequestInit) => session(url, init) ?? (
    url.includes("/dashboard/summary") ? { body: SUMMARY }
      : url.includes("/dashboard/analytics") ? { body: ANALYTICS }
      : url.includes("/events") ? { body: EVENTS } : undefined);
}

describe("authentication", () => {
  it("shows the login page when there is no session and validates input", async () => {
    mockFetch(sessionRoutes(null));
    renderApp(<App />, "/alerts");
    const button = await screen.findByRole("button", { name: "Sign in" });
    await userEvent.click(button);
    expect(screen.getByRole("alert")).toHaveTextContent("Enter your username and password");
  });

  it("shows the backend error message on failed login", async () => {
    mockFetch((url) => url.endsWith("/auth/login")
      ? { status: 401, body: { error: { code: "invalid_credentials", message: "Invalid username or password" } } }
      : sessionRoutes(null)(url));
    renderApp(<App />, "/login");
    await userEvent.type(await screen.findByLabelText("Username"), "admin");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("signs in and lands on the dashboard", async () => {
    let signedIn = false;
    const user = makeUser("viewer", VIEWER);
    mockFetch((url, init) => {
      if (url.endsWith("/auth/login")) { signedIn = true; return { body: { access_token: "tok", expires_in: 900 } }; }
      if (url.endsWith("/auth/refresh") && !signedIn) return { status: 401, body: {} };
      return dashboardRoutes(user)(url, init);
    });
    renderApp(<App />, "/login");
    await userEvent.type(await screen.findByLabelText("Username"), "viewer.user");
    await userEvent.type(screen.getByLabelText("Password"), "Correct-Horse-42!");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
  });
});

describe("role-specific navigation", () => {
  it("shows only permitted sections to a viewer", async () => {
    mockFetch(dashboardRoutes(makeUser("viewer", VIEWER)));
    renderApp(<App />);
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getByText("Alerts")).toBeInTheDocument();
    for (const hidden of ["Audit Logs", "User Management", "Settings", "AI Security Analyst", "Threat Intelligence"]) {
      expect(within(nav).queryByText(hidden)).not.toBeInTheDocument();
    }
  });

  it("shows administrative sections to an administrator", async () => {
    mockFetch(dashboardRoutes(makeUser("admin", ADMIN)));
    renderApp(<App />);
    const nav = await screen.findByRole("navigation", { name: "Main" });
    for (const label of ["Audit Logs", "User Management", "Settings", "Threat Intelligence", "AI Security Analyst"]) {
      expect(within(nav).getByText(label)).toBeInTheDocument();
    }
  });

  it("blocks direct navigation to a page outside the user's role", async () => {
    mockFetch(dashboardRoutes(makeUser("viewer", VIEWER)));
    renderApp(<App />, "/audit");
    expect(await screen.findByText("Access denied")).toBeInTheDocument();
  });
});

describe("dashboard", () => {
  it("renders statistics from the API", async () => {
    mockFetch(dashboardRoutes());
    renderApp(<App />);
    expect(await screen.findByText("6,928")).toBeInTheDocument();
    expect(screen.getByText("442")).toBeInTheDocument();
    expect(await screen.findByText("Repeated authentication failures")).toBeInTheDocument();
    expect(await screen.findByText(/login_failure: Invalid password/)).toBeInTheDocument();
  });

  it("shows an error state with retry when the API fails", async () => {
    const session = sessionRoutes(makeUser("viewer", VIEWER));
    mockFetch((url, init) => session(url, init) ?? { status: 500, body: { error: { code: "internal_error", message: "An internal error occurred. Reference: abc" } } });
    renderApp(<App />);
    expect((await screen.findAllByText(/An internal error occurred/)).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: "Try again" }).length).toBeGreaterThan(0);
  });

  it("passes the severity filter to the events API", async () => {
    const calls = mockFetch(dashboardRoutes());
    renderApp(<App />);
    await screen.findByText("6,928");
    await userEvent.selectOptions(screen.getByLabelText("Severity filter"), "critical");
    await waitFor(() => expect(calls.some((c) => c.url.includes("/events?") && c.url.includes("severity=critical"))).toBe(true));
  });
});

describe("events explorer and alert actions", () => {
  it("hides ingestion controls from viewers and shows them to analysts", async () => {
    const routes = (user: ReturnType<typeof makeUser>) => {
      const session = sessionRoutes(user);
      return (url: string, init?: RequestInit) => session(url, init) ?? (url.includes("/events/facets")
        ? { body: { source_systems: ["vpn-gw-01"], event_types: ["login_failure"], categories: ["authentication"] } }
        : url.includes("/events") ? { body: EVENTS } : undefined);
    };
    mockFetch(routes(makeUser("viewer", VIEWER)));
    const { unmount } = renderApp(<App />, "/events");
    await screen.findByText("nora.b");
    expect(screen.queryByRole("button", { name: "Upload logs" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Export CSV" })).not.toBeInTheDocument();
    unmount();
    vi.unstubAllGlobals();
    mockFetch(routes(makeUser("soc_analyst", ANALYST)));
    renderApp(<App />, "/events");
    await screen.findByText("nora.b");
    expect(screen.getByRole("button", { name: "Upload logs" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export CSV" })).toBeInTheDocument();
  });

  it("requires a reason before marking an alert as a false positive", async () => {
    const user = makeUser("soc_analyst", ANALYST);
    const session = sessionRoutes(user);
    const alert = {
      id: 3, rule_id: "SEN-AUTH-001", rule_name: "Repeated authentication failures", group_key: "username:nora.b",
      title: "Repeated authentication failures for nora.b", description: "14 failed logins", severity: "high", risk_score: 62,
      status: "new", event_count: 14, first_seen: "2026-11-11T02:14:00Z", last_seen: "2026-11-11T02:19:00Z", assigned_to: null,
      incident_id: null, incident_reference: null, is_synthetic: true, created_at: "2026-11-22T21:00:00Z",
      score_breakdown: [{ factor: "Rule base score", points: 45, explanation: "Configured base score" }], evidence_summary: { account: "nora.b" },
      rule: { id: "SEN-AUTH-001", name: "x", description: "d", category: "authentication", severity: "medium", base_score: 45, confidence: 0.8,
        parameters: {}, required_fields: [], rationale: "", investigation_steps: ["Check the source IP"], false_positive_notes: "Stale password", enabled: true, updated_at: "2026-11-22T21:00:00Z" },
      acknowledged_at: null, activity: [], events: [], events_total: 0,
    };
    const calls = mockFetch((url, init) => session(url, init) ?? (
      url.includes("/users/assignable") ? { body: [] }
        : url.includes("/alerts/3/status") ? { status: 422, body: { error: { code: "reason_required", message: "Give a reason of at least 10 characters when closing an alert" } } }
        : url.includes("/alerts/3") ? { body: alert } : undefined));
    renderApp(<App />, "/alerts/3");
    await userEvent.click(await screen.findByRole("button", { name: "Mark false positive" }));
    const dialog = screen.getByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Confirm" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Give a reason");
    expect(calls.some((c) => c.url.endsWith("/alerts/3/status") && c.init?.method === "POST")).toBe(true);
    expect(screen.getByText("Check the source IP")).toBeInTheDocument();
  });
});

describe("components", () => {
  it("renders severity and risk consistently", () => {
    render(<><SeverityBadge severity="critical" /><RiskScore score={86} /><RiskScore score={null} /></>);
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByTitle("Risk score 86 of 100")).toBeInTheDocument();
    expect(screen.getByText("-")).toBeInTheDocument();
  });
});
