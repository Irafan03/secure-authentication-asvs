import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api } from '../api/client';
import type { AuthUser } from '../api/types';

type AuthState = {
  authenticated: boolean;
  loading: boolean;
  user: AuthUser | null;
  username: string;
  message: string;
  setMessage: (value: string) => void;
  signIn: (user: AuthUser) => void;
  updateUser: (patch: Partial<AuthUser>) => void;
  clear: () => void;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState('');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const revision = useRef(0);

  useEffect(() => {
    let active = true;
    const initialRevision = revision.current;
    api.currentSession()
      .then((result) => {
        if (active && revision.current === initialRevision) setUser(result.authenticated ? result.user ?? null : null);
      })
      .catch(() => {
        if (active && revision.current === initialRevision) setUser(null);
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const value = useMemo<AuthState>(() => ({
    authenticated: user !== null,
    loading,
    user,
    username: user?.username ?? '',
    message,
    setMessage,
    signIn: (nextUser) => { revision.current += 1; setUser(nextUser); setMessage(''); },
    updateUser: (patch) => setUser((current) => current ? { ...current, ...patch } : current),
    clear: () => { revision.current += 1; setUser(null); setMessage(''); },
  }), [loading, message, user]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('AuthProvider manquant');
  return value;
}
