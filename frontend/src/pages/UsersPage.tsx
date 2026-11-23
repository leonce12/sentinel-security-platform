import { KeyRound, Plus, Search } from "lucide-react";
import { useState } from "react";

import {
  Button, Card, EmptyState, ErrorState, Field, InlineError, Input, Modal, PageHeader, Pagination, Select, Spinner,
  StatusBadge, Table, Tabs, Td, Th,
} from "../components/ui";
import { useAuth } from "../contexts/AuthContext";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Page, UserRow } from "../types/api";
import { formatShort } from "../utils/format";

interface Role { name: string; display_name: string; description: string; permissions: string[] }
interface ApiKey { id: number; name: string; prefix: string; created_at: string; last_used_at: string | null; revoked_at: string | null; key?: string }

const EMPTY = { username: "", email: "", full_name: "", password: "", role: "viewer" };

function UsersTab({ roles }: { roles: Role[] }) {
  const { user: me } = useAuth();
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const users = useApi(() => api.get<Page<UserRow>>("/users", { page, q: q || undefined }), [page, q]);
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ ...EMPTY });
  const [editing, setEditing] = useState<UserRow | null>(null);
  const [resetFor, setResetFor] = useState<UserRow | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const action = useAction();
  const roleName = (n: string) => roles.find((r) => r.name === n)?.display_name ?? n;

  async function create() {
    const ok = await action.run(() => api.post("/users", form));
    if (ok) { setCreateOpen(false); setForm({ ...EMPTY }); users.reload(); }
  }
  async function saveEdit() {
    const ok = await action.run(() => api.patch(`/users/${editing!.id}`, { role: editing!.role, is_active: editing!.is_active, full_name: editing!.full_name, email: editing!.email }));
    if (ok) { setEditing(null); users.reload(); }
  }
  async function resetPassword() {
    const ok = await action.run(() => api.post(`/users/${resetFor!.id}/reset-password`, { new_password: newPassword }));
    if (ok) { setResetFor(null); setNewPassword(""); }
  }

  return (
    <Card bodyClassName="p-3">
      <div className="mb-3 flex gap-2">
        <div className="relative max-w-xs flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-ink-faint" aria-hidden />
          <Input aria-label="Search users" placeholder="Search users" className="pl-8" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
        </div>
        <div className="flex-1" />
        <Button variant="primary" onClick={() => { action.setError(null); setCreateOpen(true); }} icon={<Plus className="h-4 w-4" />}>Add user</Button>
      </div>
      {users.error ? <ErrorState message={users.error} /> : !users.data ? <Spinner /> : users.data.items.length === 0 ? <EmptyState title="No users found" /> : (
        <>
          <Table>
            <thead><tr><Th>User</Th><Th>Email</Th><Th>Role</Th><Th>Status</Th><Th>Last sign-in</Th><Th /></tr></thead>
            <tbody>{users.data.items.map((u) => (
              <tr key={u.id}>
                <Td><div className="font-medium">{u.username}{u.id === me?.id && <span className="ml-2 text-xs text-ink-faint">(you)</span>}</div><div className="text-xs text-ink-faint">{u.full_name}</div></Td>
                <Td className="text-sm">{u.email}</Td><Td>{roleName(u.role)}</Td>
                <Td><StatusBadge status={u.is_active ? "active" : "inactive"} /></Td>
                <Td className="whitespace-nowrap text-xs">{formatShort(u.last_login_at)}</Td>
                <Td className="whitespace-nowrap text-right">
                  <Button variant="ghost" onClick={() => { action.setError(null); setEditing({ ...u }); }}>Edit</Button>
                  <Button variant="ghost" onClick={() => { action.setError(null); setResetFor(u); }}>Reset password</Button>
                </Td>
              </tr>
            ))}</tbody>
          </Table>
          <Pagination page={users.data.page} pages={users.data.pages} total={users.data.total} onPage={setPage} />
        </>
      )}

      <Modal title="Add user" open={createOpen} onClose={() => setCreateOpen(false)}
        footer={<><Button onClick={() => setCreateOpen(false)}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={create}>Create user</Button></>}>
        <Field label="Username" hint="3-64 characters: letters, digits, dot, dash, underscore"><Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>
        <Field label="Full name"><Input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></Field>
        <Field label="Email"><Input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
        <Field label="Role"><Select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{roles.map((r) => <option key={r.name} value={r.name}>{r.display_name}</option>)}</Select></Field>
        <Field label="Initial password" hint="At least 12 characters with three of: lowercase, uppercase, digit, symbol. Share it with the user through a secure channel.">
          <Input type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </Field>
        <InlineError message={action.error} />
      </Modal>

      <Modal title={`Edit ${editing?.username ?? ""}`} open={!!editing} onClose={() => setEditing(null)}
        footer={<><Button onClick={() => setEditing(null)}>Cancel</Button><Button variant="primary" busy={action.busy} onClick={saveEdit}>Save</Button></>}>
        {editing && <>
          <Field label="Full name"><Input value={editing.full_name} onChange={(e) => setEditing({ ...editing, full_name: e.target.value })} /></Field>
          <Field label="Email"><Input value={editing.email} onChange={(e) => setEditing({ ...editing, email: e.target.value })} /></Field>
          <Field label="Role"><Select value={editing.role} onChange={(e) => setEditing({ ...editing, role: e.target.value })}>{roles.map((r) => <option key={r.name} value={r.name}>{r.display_name}</option>)}</Select></Field>
          <Field label="Account status"><Select value={editing.is_active ? "active" : "inactive"} onChange={(e) => setEditing({ ...editing, is_active: e.target.value === "active" })}>
            <option value="active">Active</option><option value="inactive">Deactivated (cannot sign in)</option></Select></Field>
          <p className="text-xs text-ink-muted">{roles.find((r) => r.name === editing.role)?.description}</p>
        </>}
        <InlineError message={action.error} />
      </Modal>

      <Modal title={`Reset password for ${resetFor?.username ?? ""}`} open={!!resetFor} onClose={() => setResetFor(null)}
        footer={<><Button onClick={() => setResetFor(null)}>Cancel</Button><Button variant="danger" busy={action.busy} onClick={resetPassword}>Reset password</Button></>}>
        <p className="text-sm text-ink-muted">The user's active sessions are revoked and any lockout is cleared.</p>
        <Field label="New password"><Input type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} /></Field>
        <InlineError message={action.error} />
      </Modal>
    </Card>
  );
}

function ApiKeysTab() {
  const keys = useApi(() => api.get<ApiKey[]>("/api-keys"), []);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<ApiKey | null>(null);
  const action = useAction();
  async function create() {
    const k = await action.run(() => api.post<ApiKey>("/api-keys", { name }));
    if (k) { setCreated(k); setName(""); keys.reload(); }
  }
  return (
    <Card bodyClassName="p-3">
      <p className="mb-3 text-sm text-ink-muted">Ingestion API keys let an authorized system push events to <code className="font-mono">POST /api/v1/ingest/events</code> with an <code className="font-mono">X-API-Key</code> header. Only a hash of each key is stored.</p>
      <div className="mb-3 flex gap-2">
        <Input aria-label="Key name" placeholder="Key name, e.g. edr-connector" value={name} onChange={(e) => setName(e.target.value)} className="max-w-xs" />
        <Button variant="primary" onClick={create} busy={action.busy} disabled={name.trim().length < 3} icon={<KeyRound className="h-4 w-4" />}>Create key</Button>
      </div>
      <InlineError message={action.error} />
      {created?.key && (
        <div className="mb-3 rounded-md border border-sev-medium/40 bg-sev-medium/10 p-3 text-sm">
          <p className="mb-1 font-medium">Copy this key now. It will not be shown again.</p>
          <code className="block break-all font-mono text-xs">{created.key}</code>
        </div>
      )}
      {!keys.data ? <Spinner /> : keys.data.length === 0 ? <EmptyState title="No API keys" /> : (
        <Table>
          <thead><tr><Th>Name</Th><Th>Prefix</Th><Th>Created</Th><Th>Last used</Th><Th>Status</Th><Th /></tr></thead>
          <tbody>{keys.data.map((k) => (
            <tr key={k.id}><Td>{k.name}</Td><Td className="font-mono text-xs">{k.prefix}</Td><Td className="text-xs">{formatShort(k.created_at)}</Td>
              <Td className="text-xs">{formatShort(k.last_used_at)}</Td><Td><StatusBadge status={k.revoked_at ? "revoked" : "active"} /></Td>
              <Td className="text-right">{!k.revoked_at && <Button variant="ghost" onClick={async () => { await action.run(() => api.post(`/api-keys/${k.id}/revoke`)); keys.reload(); }}>Revoke</Button>}</Td></tr>
          ))}</tbody>
        </Table>
      )}
    </Card>
  );
}

export default function UsersPage() {
  const [tab, setTab] = useState<"users" | "roles" | "keys">("users");
  const roles = useApi(() => api.get<Role[]>("/roles"), []);
  return (
    <div>
      <PageHeader title="User management" description="Accounts, roles and machine ingestion keys. Every change is audited." />
      <Tabs tabs={[{ id: "users", label: "Users" }, { id: "roles", label: "Roles and permissions" }, { id: "keys", label: "Ingestion API keys" }]} value={tab} onChange={setTab} />
      {roles.error ? <ErrorState message={roles.error} /> : !roles.data ? <Spinner /> : (
        <>
          {tab === "users" && <UsersTab roles={roles.data} />}
          {tab === "roles" && (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {roles.data.map((r) => (
                <Card key={r.name} title={r.display_name}>
                  <p className="mb-3 text-sm text-ink-muted">{r.description}</p>
                  <div className="flex flex-wrap gap-1">{r.permissions.map((p) => <span key={p} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-muted">{p}</span>)}</div>
                </Card>
              ))}
            </div>
          )}
          {tab === "keys" && <ApiKeysTab />}
        </>
      )}
    </div>
  );
}
