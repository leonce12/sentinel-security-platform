import { Lock, Shield } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

import { Button, Field, InlineError, Input } from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { errorMessage } from "../services/api";

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
      const from = (location.state as { from?: string } | null)?.from;
      navigate(from && from !== "/login" ? from : "/", { replace: true });
    } catch (err) {
      setError(errorMessage(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Shield className="h-10 w-10 text-accent" aria-hidden />
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Sentinel</h1>
            <p className="mt-1 text-sm text-ink-muted">Security monitoring and threat detection</p>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4 rounded-lg border border-line bg-surface p-6" noValidate>
          <Field label="Username" htmlFor="username">
            <Input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </Field>
          <Field label="Password" htmlFor="password">
            <Input id="password" type="password" autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <InlineError message={error} />
          <Button type="submit" variant="primary" busy={busy} className="w-full" icon={<Lock className="h-4 w-4" />}>
            Sign in
          </Button>
        </form>
        <p className="mt-6 text-center text-xs text-ink-faint">
          Authorized use only. Sign-in attempts are recorded in the audit log.
        </p>
        <p className="mt-3 text-center text-sm">
          <Link to="/" className="text-ink-muted hover:text-ink">Back to the Sentinel home page</Link>
        </p>
      </div>
    </div>
  );
}
