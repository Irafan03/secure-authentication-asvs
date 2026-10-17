import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';
type AuthState = { authenticated: boolean; username: string; message: string; setMessage: (value: string) => void; signIn: (username: string) => void; clear: () => void };
const AuthContext = createContext<AuthState | null>(null);
export function AuthProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState('');
  const [username, setUsername] = useState('');
  const [authenticated, setAuthenticated] = useState(false);
  const value = useMemo(() => ({ authenticated, username, message, setMessage, signIn: (name: string) => { setUsername(name); setAuthenticated(true); }, clear: () => { setAuthenticated(false); setUsername(''); setMessage(''); } }), [authenticated, username, message]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
export function useAuth() { const value = useContext(AuthContext); if (!value) throw new Error('AuthProvider manquant'); return value; }
