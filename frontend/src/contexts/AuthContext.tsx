import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import { api, refreshSession, setAccessToken, setSessionExpiredHandler } from "../services/api";
import type { Me } from "../types/api";

interface AuthState {
  user: Me | null;
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  reloadUser: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);

  const reloadUser = useCallback(async () => {
    setUser(await api.get<Me>("/auth/me"));
  }, []);

  // On first load, try to restore the session from the HttpOnly refresh cookie.
  useEffect(() => {
    setSessionExpiredHandler(() => setUser(null));
    (async () => {
      if (await refreshSession()) {
        try {
          await reloadUser();
        } catch {
          setUser(null);
        }
      }
      setReady(true);
    })();
    return () => setSessionExpiredHandler(null);
  }, [reloadUser]);

  const login = useCallback(
    async (username: string, password: string) => {
      const tokens = await api.post<{ access_token: string }>("/auth/login", { username, password });
      setAccessToken(tokens.access_token);
      await reloadUser();
    },
    [reloadUser],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setAccessToken(null);
      setUser(null);
    }
  }, []);

  // UI-only convenience: the backend enforces every permission independently.
  const can = useCallback((permission: string) => !!user?.permissions.includes(permission), [user]);

  const value = useMemo(() => ({ user, ready, login, logout, reloadUser, can }), [user, ready, login, logout, reloadUser, can]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
