import { useState } from "react";

import { Button, Card, Field, InlineError, Input, KeyValue, PageHeader } from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction } from "../hooks/useApi";
import { api } from "../services/api";
import { formatDateTime } from "../utils/format";

export default function ProfilePage() {
  const { user, reloadUser, logout } = useAuth();
  const [fullName, setFullName] = useState(user?.full_name ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [saved, setSaved] = useState(false);
  const profile = useAction();
  const password = useAction();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");

  async function saveProfile() {
    setSaved(false);
    const ok = await profile.run(() => api.patch("/auth/me", { full_name: fullName, email }));
    if (ok) { await reloadUser(); setSaved(true); }
  }

  async function changePassword() {
    if (next !== confirm) return password.setError("The new passwords do not match.");
    const ok = await password.run(() => api.post("/auth/change-password", { current_password: current, new_password: next }));
    if (ok) await logout(); // all sessions were revoked; sign in again with the new password
  }

  if (!user) return null;
  if (user.is_demo) {
    return (
      <div>
        <PageHeader title="Demo account" />
        <Card title="Read-only demo">
          <p className="text-sm text-ink-muted">
            You are signed in to the shared demo account with the Read-Only Viewer role. You can explore the dashboard,
            security events, alerts, incidents, detection rules and reports. Changes, uploads and administrative pages
            are not available, and the backend refuses them even if requested directly.
          </p>
          <div className="mt-4 flex flex-wrap gap-1">{user.permissions.map((p) => <span key={p} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-muted">{p}</span>)}</div>
        </Card>
      </div>
    );
  }
  return (
    <div>
      <PageHeader title="Your profile" />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Account">
          <KeyValue items={[["Username", user.username], ["Role", user.role_display_name], ["Last sign-in", formatDateTime(user.last_login_at)], ["Member since", formatDateTime(user.created_at)]]} />
          <div className="mt-4 space-y-3">
            <Field label="Full name"><Input value={fullName} onChange={(e) => setFullName(e.target.value)} /></Field>
            <Field label="Email"><Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
            <InlineError message={profile.error} />
            {saved && <p className="text-sm text-sev-low">Profile saved.</p>}
            <Button variant="primary" busy={profile.busy} onClick={saveProfile}>Save profile</Button>
          </div>
        </Card>
        <Card title="Change password">
          <div className="space-y-3">
            <Field label="Current password"><Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /></Field>
            <Field label="New password" hint="At least 12 characters with three of: lowercase, uppercase, digit, symbol."><Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></Field>
            <Field label="Repeat new password"><Input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></Field>
            <InlineError message={password.error} />
            <p className="text-xs text-ink-faint">Changing your password signs you out everywhere.</p>
            <Button variant="primary" busy={password.busy} disabled={!current || !next} onClick={changePassword}>Change password</Button>
          </div>
        </Card>
        <Card title="Your permissions" className="lg:col-span-2">
          <div className="flex flex-wrap gap-1">{user.permissions.map((p) => <span key={p} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-muted">{p}</span>)}</div>
        </Card>
      </div>
    </div>
  );
}
