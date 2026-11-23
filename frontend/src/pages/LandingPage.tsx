import {
  Activity, ArrowRight, Bot, ExternalLink, FileText, Gauge, Globe, LogIn, ScrollText, Shield, ShieldAlert, Siren,
} from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { Button, InlineError } from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useApi } from "../hooks/useApi";
import { api, errorMessage } from "../services/api";

const REPO_URL = "https://github.com/soniaineza/sentinel-security-platform";

const FEATURES = [
  { icon: Activity, title: "Log ingestion", text: "CSV, JSON and API ingestion with validation, UTC normalization, duplicate detection and a report of every rejected record." },
  { icon: ShieldAlert, title: "Deterministic detection", text: "Ten documented rules: brute force and password spraying, privilege escalation, disabled security controls, traffic spikes and more." },
  { icon: Gauge, title: "Explainable risk scores", text: "Every alert shows the factors behind its 0 to 100 score, with safeguards against counting the same evidence twice." },
  { icon: Siren, title: "Incident response", text: "High-risk alerts open incidents automatically and are correlated by account and IP. Analysts assign, annotate and resolve." },
  { icon: Globe, title: "Threat intelligence", text: "Offline reputation data with optional external lookups. Missing information is never treated as safe." },
  { icon: Bot, title: "AI that explains, not decides", text: "Optional AI explanations from minimized data, with a built-in explanation that always works offline." },
  { icon: FileText, title: "Reports and exports", text: "Daily, weekly and incident PDF reports with SHA-256 hashes, and CSV exports protected against formula injection." },
  { icon: ScrollText, title: "Secure by design", text: "Argon2id, rotating session cookies, role checks on every endpoint and an append-only audit log enforced by the database." },
];

export default function LandingPage() {
  const { loginDemo } = useAuth();
  const navigate = useNavigate();
  const config = useApi(() => api.get<{ public_demo: boolean }>("/auth/public-config"), []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function startDemo() {
    setBusy(true);
    setError(null);
    try {
      await loginDemo();
      navigate("/", { replace: true });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-full">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-accent" aria-hidden />
            <span className="text-base font-semibold tracking-wide">Sentinel</span>
          </div>
          <nav className="flex items-center gap-2 text-sm" aria-label="Site">
            <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="hidden items-center gap-1 rounded-md px-3 py-2 text-ink-muted hover:text-ink sm:inline-flex">
              Source code <ExternalLink className="h-3.5 w-3.5" aria-hidden />
            </a>
            <Link to="/login" className="inline-flex items-center gap-2 rounded-md border border-line-strong px-3 py-2 hover:border-ink-faint">
              <LogIn className="h-4 w-4" aria-hidden /> Sign in
            </Link>
          </nav>
        </div>
      </header>

      <main>
        <section className="mx-auto max-w-6xl px-4 pb-10 pt-14 sm:px-6 sm:pt-20">
          <p className="mb-3 text-sm font-medium uppercase tracking-wider text-accent">Defensive security monitoring</p>
          <h1 className="max-w-3xl text-3xl font-semibold leading-tight tracking-tight sm:text-5xl">
            Find the events that matter, and explain why they matter.
          </h1>
          <p className="mt-5 max-w-2xl text-base text-ink-muted sm:text-lg">
            Sentinel is a working security monitoring and threat detection platform: it ingests security logs, detects
            suspicious activity with transparent rules, scores risk with a documented formula and supports analysts from
            alert to closed incident.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            {config.data?.public_demo && (
              <Button variant="primary" onClick={startDemo} busy={busy} className="h-11 px-5 text-base" icon={<ArrowRight className="h-4 w-4" />}>
                Explore the live demo
              </Button>
            )}
            <Link to="/login" className="inline-flex h-11 items-center rounded-md border border-line-strong px-5 text-base hover:border-ink-faint">
              Sign in
            </Link>
          </div>
          {config.data?.public_demo && (
            <p className="mt-3 max-w-2xl text-sm text-ink-faint">
              The demo opens a read-only Viewer account with a synthetic week of security events. Nothing can be changed.
              If the site has been idle, the first request can take up to a minute while the free server wakes up.
            </p>
          )}
          <div className="mt-4 max-w-xl"><InlineError message={error} /></div>
        </section>

        <section className="mx-auto max-w-6xl px-4 sm:px-6" aria-label="Screenshot">
          <img src="/landing-dashboard.png" alt="Sentinel dashboard showing security events, alerts by severity and authentication activity"
            className="w-full rounded-lg border border-line shadow-2xl" width={1500} height={950} />
        </section>

        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6" aria-labelledby="features">
          <h2 id="features" className="mb-8 text-xl font-semibold">What it does</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <div key={title} className="rounded-lg border border-line bg-surface p-5">
                <Icon className="mb-3 h-5 w-5 text-accent" aria-hidden />
                <h3 className="font-medium">{title}</h3>
                <p className="mt-2 text-sm text-ink-muted">{text}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-4 pb-16 sm:px-6">
          <div className="rounded-lg border border-line bg-surface p-6 text-sm text-ink-muted">
            <h2 className="mb-2 text-base font-semibold text-ink">About this deployment</h2>
            <p>
              All data on this site is synthetic: fictional users, the reserved <span className="font-mono">corp.example</span> domain and
              documentation-only IP ranges. Built with FastAPI, PostgreSQL, React and TypeScript. Detection, scoring and
              reporting run without any external service or AI key.
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-6 text-sm text-ink-faint sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <span>Sentinel · built by Ineza Sonia · MIT License</span>
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 hover:text-ink">
            github.com/soniaineza/sentinel-security-platform <ExternalLink className="h-3.5 w-3.5" aria-hidden />
          </a>
        </div>
      </footer>
    </div>
  );
}
