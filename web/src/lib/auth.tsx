"use client";

/**
 * Client-side session state. Holds the `/v2` Bearer token + org id in
 * localStorage and exposes `login` / `signup` / `logout` plus the current
 * token. This is a deliberately small, dependency-free auth layer; when SSR /
 * httpOnly-cookie sessions are needed, swap the storage for a cookie set by a
 * Next.js route handler — the component API here stays the same.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { api } from "./api";

const TOKEN_KEY = "recupero.token";
const ORG_KEY = "recupero.org";

interface AuthState {
  token: string | null;
  orgId: string | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string, orgName: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [orgId, setOrgId] = useState<string | null>(null);
  const [ready, setReady] = useState(false);

  // Hydrate from localStorage on mount (client-only).
  useEffect(() => {
    setToken(localStorage.getItem(TOKEN_KEY));
    setOrgId(localStorage.getItem(ORG_KEY));
    setReady(true);
  }, []);

  const persist = useCallback((t: string, org: string) => {
    localStorage.setItem(TOKEN_KEY, t);
    localStorage.setItem(ORG_KEY, org);
    setToken(t);
    setOrgId(org);
  }, []);

  const login = useCallback(
    async (email: string, password: string) => {
      const out = await api.login(email, password);
      persist(out.access_token, out.org_id);
    },
    [persist],
  );

  const signup = useCallback(
    async (email: string, password: string, orgName: string) => {
      const out = await api.signup(email, password, orgName);
      persist(out.access_token, out.org_id);
    },
    [persist],
  );

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ORG_KEY);
    setToken(null);
    setOrgId(null);
  }, []);

  const value = useMemo<AuthState>(
    () => ({ token, orgId, ready, login, signup, logout }),
    [token, orgId, ready, login, signup, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
