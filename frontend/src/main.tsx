import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './auth/AuthContext';
import { ChangeIdentity, ChangePassword, Dashboard, EnrollMfa, ForgotPassword, Home, Login, MfaLogin, MfaRecovery, MfaRecoveryConfirm, Register, ResetPassword, SecurityActivity, AdminReset, ProtectedRoute } from './pages/Pages';
import './style.css';

function App() { return <BrowserRouter><AuthProvider><Routes>
  <Route path="/" element={<Home />} /><Route path="/register" element={<Register />} /><Route path="/login" element={<Login />} /><Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} /><Route path="/login/mfa" element={<MfaLogin />} />
  <Route path="/password-reset" element={<ForgotPassword />} /><Route path="/password-reset/confirm" element={<ResetPassword />} /><Route path="/mfa/recovery" element={<MfaRecovery />} /><Route path="/mfa/recovery/confirm" element={<MfaRecoveryConfirm />} />
  <Route path="/account/mfa" element={<ProtectedRoute><EnrollMfa /></ProtectedRoute>} /><Route path="/account/password" element={<ProtectedRoute><ChangePassword /></ProtectedRoute>} /><Route path="/account/identity" element={<ProtectedRoute><ChangeIdentity /></ProtectedRoute>} /><Route path="/account/security-activity" element={<ProtectedRoute><SecurityActivity /></ProtectedRoute>} /><Route path="/admin/password-reset" element={<ProtectedRoute><AdminReset /></ProtectedRoute>} />
  <Route path="*" element={<main className="card"><h1>Page introuvable</h1><Link to="/">Accueil</Link></main>} />
</Routes></AuthProvider></BrowserRouter>; }
ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
