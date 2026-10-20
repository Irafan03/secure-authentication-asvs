import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AuthProvider } from '../auth/AuthContext';
import { ChangePassword, Dashboard, EnrollMfa, ForgotPassword, Login, MfaRecovery, ProtectedRoute, Register, ResetPassword } from './Pages';

const server = setupServer(
  http.get('http://localhost:3000/api/auth/session', () => HttpResponse.json({ authenticated: false }, { status: 401 })),
  http.post('http://localhost:3000/login', async ({ request }) => {
    const body = await request.json() as { username: string; password: string; totp_code?: string };
    if (body.username === 'alice' && body.password === 'correct horse battery staple') return HttpResponse.json({ success: true, user: { id: 1, username: 'alice', email: 'alice@example.test', role: 'user' } });
    return HttpResponse.json({ success: false, errors: ['Identifiant ou mot de passe incorrect.'] }, { status: 401 });
  }),
  http.post('http://localhost:3000/register', async () => HttpResponse.json({ success: true, message: 'Compte créé. Vous pouvez maintenant vous connecter.' }, { status: 201 })),
  http.post('http://localhost:3000/api/auth/logout', async () => HttpResponse.json({ success: true, message: 'Déconnexion réussie.' })),
  http.post('http://localhost:3000/api/account/password', async () => HttpResponse.json({ success: true, message: 'Mot de passe changé avec succès.' })),
  http.post('http://localhost:3000/api/account/mfa/enrollment', async () => HttpResponse.json({ success: true, secret: 'TESTSECRET', qr_code_uri: 'otpauth://totp/SecureAuth:alice?secret=TESTSECRET', recovery_codes: ['AAAA-BBBB'] })),
  http.post('http://localhost:3000/api/account/mfa/enrollment/confirm', async () => HttpResponse.json({ success: true, message: 'Authentification MFA activée.' })),
  http.post('http://localhost:3000/password-reset', async () => HttpResponse.json({ success: true, message: 'Si le compte existe, les instructions ont été envoyées.' })),
  http.post('http://localhost:3000/password-reset/confirm', async () => HttpResponse.json({ success: true, message: 'Réinitialisation effectuée.' })),
);
beforeAll(() => server.listen({ onUnhandledRequest: 'error' })); afterEach(() => { cleanup(); server.resetHandlers(); }); afterAll(() => server.close());
function renderApp(element: ReactNode) { return render(<MemoryRouter><AuthProvider>{element}</AuthProvider></MemoryRouter>); }

describe('frontend security behavior', () => {
  it('renders password as password and toggles visibility accessibly', async () => {
    window.history.replaceState({}, '', '/password-reset/confirm?token=sample');
    renderApp(<ResetPassword />); const field = screen.getByLabelText('Nouveau mot de passe');
    expect(field).toHaveAttribute('type', 'password'); expect(field).toHaveAttribute('autoComplete', 'new-password'); expect(field).toHaveAttribute('maxLength', '128');
    await userEvent.click(screen.getByRole('button', { name: 'Afficher le mot de passe' })); expect(field).toHaveAttribute('type', 'text'); expect(screen.getByRole('button', { name: 'Masquer le mot de passe' })).toHaveAttribute('aria-pressed', 'true');
  });
  it('does not cancel password pasting', () => {
    window.history.replaceState({}, '', '/password-reset/confirm?token=sample'); renderApp(<ResetPassword />); const field = screen.getByLabelText('Nouveau mot de passe');
    const event = new Event('paste', { bubbles: true, cancelable: true }); field.dispatchEvent(event); expect(event.defaultPrevented).toBe(false);
  });
  it('accepts successful login and routes to the protected dashboard', async () => {
    render(<MemoryRouter initialEntries={['/login']}><AuthProvider><Routes><Route path="/login" element={<Login />} /><Route path="/dashboard" element={<ProtectedRoute><p>Session ouverte</p></ProtectedRoute>} /></Routes></AuthProvider></MemoryRouter>);
    await userEvent.type(screen.getByLabelText("Nom d'utilisateur"), 'alice'); await userEvent.type(screen.getByLabelText('Mot de passe'), 'correct horse battery staple'); await userEvent.click(screen.getByRole('button', { name: 'Se connecter' }));
    expect(await screen.findByText('Session ouverte')).toBeInTheDocument();
  });
  it('submits an MFA code with the login request', async () => {
    render(<MemoryRouter initialEntries={['/login']}><AuthProvider><Routes><Route path="/login" element={<Login />} /><Route path="/dashboard" element={<ProtectedRoute><p>Session ouverte avec MFA</p></ProtectedRoute>} /></Routes></AuthProvider></MemoryRouter>);
    await userEvent.type(screen.getByLabelText("Nom d'utilisateur"), 'alice'); await userEvent.type(screen.getByLabelText('Mot de passe'), 'correct horse battery staple');
    await userEvent.click(screen.getByRole('button', { name: 'Mon compte utilise un code MFA' })); const code = screen.getByLabelText('Code TOTP');
    expect(code).toHaveAttribute('inputmode', 'numeric'); expect(code).toHaveAttribute('autocomplete', 'one-time-code'); await userEvent.type(code, '123456'); await userEvent.click(screen.getByRole('button', { name: 'Se connecter' }));
    expect(await screen.findByText('Session ouverte avec MFA')).toBeInTheDocument();
  });
  it('shows one generic message after invalid credentials', async () => {
    renderApp(<Login />); await userEvent.type(screen.getByLabelText("Nom d'utilisateur"), 'unknown'); await userEvent.type(screen.getByLabelText('Mot de passe'), 'wrong password'); await userEvent.click(screen.getByRole('button', { name: 'Se connecter' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Identifiant ou mot de passe incorrect.');
  });
  it('posts registration and shows a neutral success message', async () => {
    renderApp(<Register />); await userEvent.type(screen.getByLabelText("Nom d'utilisateur"), 'alice'); await userEvent.type(screen.getByLabelText('Adresse e-mail'), 'alice@example.test');
    await userEvent.type(screen.getByLabelText('Mot de passe', { selector: 'input' }), 'a long passphrase'); await userEvent.type(screen.getByLabelText('Confirmer le mot de passe'), 'a long passphrase');
    await userEvent.click(screen.getByRole('button', { name: 'Créer mon compte' })); expect(await screen.findByRole('status')).toHaveTextContent(/vous pouvez maintenant vous connecter/i);
  });
  it('completes a two-step MFA login without clearing the password before the code', async () => {
    let attempts = 0;
    server.use(http.post('http://localhost:3000/login', async ({ request }) => {
      attempts += 1;
      const body = await request.json() as { password: string; totp_code?: string };
      if (attempts === 1) return HttpResponse.json({ success: false, mfa_required: true, errors: ['MFA requis'] });
      expect(body.password).toBe('correct horse battery staple');
      expect(body.totp_code).toBe('123456');
      return HttpResponse.json({ success: true, user: { id: 1, username: 'alice', email: 'alice@example.test', role: 'user', mfa_enabled: true } });
    }));
    render(<MemoryRouter initialEntries={['/login']}><AuthProvider><Routes><Route path="/login" element={<Login />} /><Route path="/dashboard" element={<ProtectedRoute><p>Session MFA</p></ProtectedRoute>} /></Routes></AuthProvider></MemoryRouter>);
    await userEvent.type(screen.getByLabelText("Nom d'utilisateur"), 'alice');
    await userEvent.type(screen.getByLabelText('Mot de passe'), 'correct horse battery staple');
    await userEvent.click(screen.getByRole('button', { name: 'Se connecter' }));
    await screen.findByLabelText('Code TOTP');
    await userEvent.type(screen.getByLabelText('Code TOTP'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Se connecter' }));
    expect(await screen.findByText('Session MFA')).toBeInTheDocument();
  });
  it('changes the password through the account API', async () => {
    renderApp(<ChangePassword />);
    await userEvent.type(screen.getByLabelText('Mot de passe actuel'), 'old passphrase');
    await userEvent.type(screen.getByLabelText('Nouveau mot de passe'), 'new long passphrase');
    await userEvent.type(screen.getByLabelText('Confirmer le nouveau mot de passe'), 'new long passphrase');
    await userEvent.click(screen.getByRole('button', { name: 'Modifier le mot de passe' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Mot de passe changé avec succès.');
  });
  it('enrolls TOTP and requires saving recovery codes before confirmation', async () => {
    renderApp(<EnrollMfa />);
    await userEvent.click(screen.getByRole('button', { name: 'Configurer la MFA' }));
    expect(await screen.findByText('TESTSECRET')).toBeInTheDocument();
    const confirm = screen.getByRole('button', { name: 'Confirmer et activer la MFA' });
    expect(confirm).toBeDisabled();
    await userEvent.click(screen.getByRole('checkbox', { name: /J’ai conservé/ }));
    await userEvent.type(screen.getByLabelText('Code TOTP'), '123456');
    await userEvent.click(confirm);
    expect(await screen.findByRole('status')).toHaveTextContent('Authentification MFA activée.');
  });
  it('accepts a 128 character password without composition rules and preserves whitespace', async () => {
    window.history.replaceState({}, '', '/password-reset/confirm?token=abc'); renderApp(<ResetPassword />);
    const field = screen.getByLabelText('Nouveau mot de passe'); const value = ` ${'a'.repeat(127)}`;
    await userEvent.type(field, value); expect(field).toHaveValue(value); expect(screen.queryByText(/majuscule|symbole|chiffre/i)).not.toBeInTheDocument();
  });
  it('posts the reset request and shows the neutral response', async () => {
    renderApp(<ForgotPassword />); await userEvent.type(screen.getByLabelText(/Nom d'utilisateur/), 'user@example.test'); await userEvent.click(screen.getByRole('button', { name: 'Envoyer les instructions' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Si le compte existe');
  });
  it('requests MFA recovery with an identifier and does not reveal account existence', async () => {
    let submittedIdentifier = '';
    server.use(http.post('http://localhost:3000/mfa/recovery/request', async ({ request }) => {
      submittedIdentifier = (await request.json() as { identifier: string }).identifier;
      return HttpResponse.json({ success: true, message: 'Si le compte peut être récupéré, les instructions ont été envoyées.' });
    }));
    renderApp(<MfaRecovery />);
    await userEvent.type(screen.getByLabelText(/Nom d'utilisateur/), 'alice@example.test');
    await userEvent.click(screen.getByRole('button', { name: 'Envoyer un lien de récupération' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Si le compte peut être récupéré');
    expect(submittedIdentifier).toBe('alice@example.test');
  });
  it('redirects protected routes to login', async () => {
    render(<MemoryRouter initialEntries={['/private']}><AuthProvider><Routes><Route path="/private" element={<ProtectedRoute><p>private</p></ProtectedRoute>} /><Route path="/login" element={<p>Connexion requise</p>} /></Routes></AuthProvider></MemoryRouter>);
    await waitFor(() => expect(screen.getByText('Connexion requise')).toBeInTheDocument());
  });
  it('restores an existing HttpOnly session through the session endpoint', async () => {
    server.use(http.get('http://localhost:3000/api/auth/session', () => HttpResponse.json({ authenticated: true, user: { id: 1, username: 'alice', email: 'alice@example.test', role: 'user', mfa_enabled: true } })));
    render(<MemoryRouter initialEntries={['/dashboard']}><AuthProvider><Routes><Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} /><Route path="/login" element={<p>Connexion requise</p>} /></Routes></AuthProvider></MemoryRouter>);
    expect(await screen.findByText('Bienvenue, alice')).toBeInTheDocument();
    expect(screen.getByText('activée')).toBeInTheDocument();
  });
  it('does not persist request values or print to the console', async () => {
    const log = vi.spyOn(console, 'log'); renderApp(<ForgotPassword />); await userEvent.type(screen.getByLabelText(/Nom d'utilisateur/), 'alice@example.test'); await userEvent.click(screen.getByRole('button', { name: 'Envoyer les instructions' })); await screen.findByRole('status');
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0); expect(log).not.toHaveBeenCalled(); log.mockRestore();
  });
});
