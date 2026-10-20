import { useEffect, useState, type ReactNode } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { QRCodeSVG } from 'qrcode.react';
import { api, ApiException } from '../api/client';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '../config/constants';
import { useAuth } from '../auth/AuthContext';
import { PasswordField } from '../components/PasswordField';

type ResetFields = { new_password: string; confirmation: string; totp_code?: string; recovery_code?: string };
const password = z.string().min(PASSWORD_MIN_LENGTH, `Au moins ${PASSWORD_MIN_LENGTH} caractères.`).max(PASSWORD_MAX_LENGTH, `Au plus ${PASSWORD_MAX_LENGTH} caractères.`);

function Shell({ title, children }: { title: string; children: ReactNode }) {
  const auth = useAuth();
  return <div className="app-frame"><div className="ambient ambient-one" aria-hidden="true" /><div className="ambient ambient-two" aria-hidden="true" /><main className="auth-card"><header className="site-header"><Link to="/" className="brand"><span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5.2-3.4 8.4-8 10-4.6-1.6-8-4.8-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></svg></span><span className="brand-copy"><strong>SecureAuth</strong><small>Identity workspace</small></span></Link><nav className="header-nav" aria-label="Navigation principale">{auth.authenticated ? auth.user?.mfa_enrollment_required ? <Link to="/account/mfa">Configurer la MFA</Link> : <Link to="/dashboard">Mon compte</Link> : <><Link to="/login">Connexion</Link><Link className="nav-cta" to="/register">Créer un compte</Link></>}</nav></header><div className="auth-content"><p className="eyebrow">ESPACE SÉCURISÉ</p><h1>{title}</h1>{children}</div><footer className="auth-footer"><span><i aria-hidden="true" /> Session protégée</span><span>SecureAuth · Protection de compte</span></footer></main></div>;
}

function FormError({ children }: { children: ReactNode }) { return <p className="error" role="alert" aria-live="polite">{children}</p>; }
function formErrors(errors: Record<string, { message?: string } | undefined>) { return Object.values(errors).filter(Boolean).map((error) => error?.message).join(' '); }

export function Home() {
  const auth = useAuth();
  return <Shell title="Votre identité numérique, sous contrôle"><p className="lead">Un espace simple pour gérer votre compte, vos accès et votre sécurité.</p><div className="home-feature"><span className="feature-icon" aria-hidden="true">✦</span><div><strong>Une protection renforcée</strong><p>La double authentification protège chaque connexion à votre compte.</p></div></div><div className="home-actions">{auth.authenticated ? auth.user?.mfa_enrollment_required ? <Link className="button-link" to="/account/mfa">Configurer la double authentification <span aria-hidden="true">→</span></Link> : <Link className="button-link" to="/dashboard">Ouvrir mon espace <span aria-hidden="true">→</span></Link> : <><Link className="button-link" to="/register">Créer un compte <span aria-hidden="true">→</span></Link><Link className="text-link" to="/login">J’ai déjà un compte</Link></>}</div><div className="trust-row"><span>Connexion chiffrée</span><span>·</span><span>Session privée</span><span>·</span><span>MFA obligatoire</span></div></Shell>;
}

export function Register() {
  const schema = z.object({ username: z.string().min(3, 'Au moins 3 caractères.'), email: z.string().email('Adresse e-mail invalide.'), password, password_confirm: z.string() }).refine((values) => values.password === values.password_confirm, { path: ['password_confirm'], message: 'Les mots de passe ne correspondent pas.' });
  const { register, handleSubmit, formState: { errors, isSubmitting }, reset } = useForm<{ username: string; email: string; password: string; password_confirm: string }>({ resolver: zodResolver(schema) });
  const [message, setMessage] = useState(''); const [error, setError] = useState('');
  const submit = handleSubmit(async (values) => { setMessage(''); setError(''); try { const result = await api.submitRegistration(values); setMessage(result.message ?? 'Compte créé. Vous pouvez maintenant vous connecter.'); reset(); } catch (e) { setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'Le service est momentanément indisponible.'); } });
  return <Shell title="Créer un compte"><form onSubmit={submit} noValidate><div className="field"><label htmlFor="username">Nom d'utilisateur</label><input id="username" autoComplete="username" {...register('username')} /></div><div className="field"><label htmlFor="email">Adresse e-mail</label><input id="email" type="email" autoComplete="email" {...register('email')} /></div><PasswordField id="password" name="password" label="Mot de passe" autoComplete="new-password" register={register('password')} /><PasswordField id="password_confirm" name="password_confirm" label="Confirmer le mot de passe" autoComplete="new-password" register={register('password_confirm')} />{formErrors(errors) && <FormError>{formErrors(errors)}</FormError>}<p>Choisissez une phrase de passe de 12 à 128 caractères. Aucune règle de composition n'est imposée.</p>{error && <FormError>{error}</FormError>}{message && <p role="status" aria-live="polite">{message}</p>}<button disabled={isSubmitting}>{isSubmitting ? 'Création…' : 'Créer mon compte'}</button></form></Shell>;
}

export function Login() {
  const navigate = useNavigate(); const auth = useAuth();
  const [factor, setFactor] = useState<'none' | 'totp' | 'recovery'>('none'); const [mfaChallenge, setMfaChallenge] = useState(false); const [error, setError] = useState(''); const [lockedUntil, setLockedUntil] = useState(''); const [clockNow, setClockNow] = useState(Date.now());
  const { register, handleSubmit, formState: { isSubmitting }, reset } = useForm<{ username: string; password: string; totp_code: string; recovery_code: string }>();
  const isLocked = Boolean(lockedUntil && Date.parse(lockedUntil) > clockNow);
  useEffect(() => { if (!lockedUntil) return; const timer = window.setInterval(() => setClockNow(Date.now()), 1000); return () => window.clearInterval(timer); }, [lockedUntil]);
  const submit = handleSubmit(async (values) => {
    setError('');
    try {
      const result = await api.submitLogin({ username: values.username, password: values.password, ...(factor === 'totp' ? { totp_code: values.totp_code } : {}), ...(factor === 'recovery' ? { recovery_code: values.recovery_code } : {}) });
      if (result.mfa_required) { setMfaChallenge(true); setFactor('totp'); setError('Mot de passe vérifié. Entrez votre code TOTP ou choisissez un code de récupération.'); return; }
      if (result.success && result.user) { auth.signIn(result.user); reset(); navigate(result.mfa_enrollment_required ? '/account/mfa' : '/dashboard', { replace: true }); return; }
      setMfaChallenge(false); setError(result.errors?.[0] ?? 'Identifiant ou mot de passe incorrect.'); reset({ username: values.username, password: '', totp_code: '', recovery_code: '' });
    } catch (e) {
      if (e instanceof ApiException && e.status === 423) { setLockedUntil(e.payload?.locked_until ?? ''); setError(e.payload?.errors?.[0] ?? e.message); }
      else if (e instanceof ApiException && e.status === 401) setError('Identifiant ou mot de passe incorrect.');
      else setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'Le service est momentanément indisponible.');
      setMfaChallenge(false); reset({ username: values.username, password: '', totp_code: '', recovery_code: '' });
    }
  });
  const remaining = Math.max(0, Math.ceil((Date.parse(lockedUntil) - clockNow) / 1000));
  return <Shell title="Connexion"><form onSubmit={submit} noValidate><div className="field"><label htmlFor="username">Nom d'utilisateur ou adresse e-mail</label><input id="username" autoComplete="username" {...register('username', { required: true })} /></div>{!mfaChallenge && <PasswordField id="password" name="password" label="Mot de passe" autoComplete="current-password" register={register('password', { required: true })} />}{factor === 'totp' && <div className="field"><label htmlFor="totp_code">Code TOTP</label><input id="totp_code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} {...register('totp_code')} /></div>}{factor === 'recovery' && <div className="field"><label htmlFor="recovery_code">Code de récupération</label><input id="recovery_code" autoComplete="off" {...register('recovery_code')} /></div>}<button type="button" className="secondary" onClick={() => setFactor(factor === 'none' ? 'totp' : factor === 'totp' ? 'recovery' : 'totp')}>{factor === 'none' ? 'Mon compte utilise un code MFA' : factor === 'totp' ? 'Utiliser un code de récupération' : 'Utiliser un code TOTP'}</button>{error && <FormError>{error}{isLocked && <span> Réessayez dans {remaining} s.</span>}</FormError>}<button disabled={isSubmitting || isLocked}>{isSubmitting ? 'Connexion…' : 'Se connecter'}</button></form><p><Link to="/password-reset">Mot de passe oublié ?</Link></p><p><Link to="/mfa/recovery">J'ai perdu mon application et mes codes MFA</Link></p></Shell>;
}

export function Dashboard() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const user = auth.user;

  async function signOut() {
    setBusy(true);
    setError('');
    try {
      await api.logout();
      auth.clear();
      navigate('/login', { replace: true });
    } catch {
      setError('La déconnexion a échoué.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dashboard-app">
      <header className="dashboard-header">
        <Link to="/" className="brand">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5.2-3.4 8.4-8 10-4.6-1.6-8-4.8-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></svg>
          </span>
          <span className="brand-copy"><strong>SecureAuth</strong><small>Identity workspace</small></span>
        </Link>
        <nav className="dashboard-nav" aria-label="Navigation du compte">
          <a className="active" href="#overview">Vue d’ensemble</a>
          <Link to="/account/mfa">Sécurité</Link>
          <Link to="/account/password">Mot de passe</Link>
        </nav>
        <div className="header-account">
          <span className="avatar" aria-hidden="true">{user?.username?.slice(0, 1).toUpperCase() || 'U'}</span>
          <span className="header-username">{user?.username}</span>
          <button className="logout-button" onClick={signOut} disabled={busy}>{busy ? 'Déconnexion…' : 'Quitter'}</button>
        </div>
      </header>

      <main className="dashboard-content" id="overview">
        <div className="dashboard-intro">
          <div>
            <p className="eyebrow">ESPACE PERSONNEL</p>
            <h1>Bonjour, {user?.username || 'utilisateur'}</h1>
            <p>Gérez votre compte et gardez le contrôle de vos accès.</p>
          </div>
          <span className="status-pill"><i aria-hidden="true" />Compte actif</span>
        </div>

        <section className="welcome-panel" aria-labelledby="welcome-title">
          <div className="welcome-copy">
            <span className="panel-kicker">VOTRE ESPACE SECUREAUTH</span>
            <h2 id="welcome-title">Votre compte est prêt.</h2>
            <p>Retrouvez ici les réglages importants de votre identité et de votre sécurité.</p>
            <Link className="panel-link" to="/account/mfa">Consulter mes réglages <span aria-hidden="true">→</span></Link>
          </div>
          <div className="shield-art" aria-hidden="true">
            <div className="shield-orbit orbit-one" />
            <div className="shield-orbit orbit-two" />
            <div className="shield-core"><svg viewBox="0 0 48 48"><path d="M24 5 40 11v10c0 10-6.8 17.3-16 21-9.2-3.7-16-11-16-21V11L24 5Z"/><path d="m16 24 5.3 5.3L32.5 18"/></svg></div>
            <span className="spark spark-one">✦</span><span className="spark spark-two">✧</span>
          </div>
        </section>

        <div className="section-heading">
          <div><p className="eyebrow">VOTRE COMPTE</p><h2>Vue d’ensemble</h2></div>
        </div>
        <section className="dashboard-grid" aria-label="État du compte et raccourcis">
          <article className="surface-card security-card">
            <div className="card-heading"><span className="round-icon green-icon" aria-hidden="true">✓</span><span className="card-label">SÉCURITÉ</span></div>
            <h3>Double authentification</h3>
            <p>Une étape de vérification supplémentaire protège votre connexion.</p>
            <div className="card-status"><span className="status-dot" />{user?.mfa_enabled ? 'Activée et obligatoire' : 'Configuration requise'}</div>
            <Link className="card-action" to="/account/mfa">{user?.mfa_enabled ? 'Gérer la MFA' : 'Configurer la MFA'} <span aria-hidden="true">→</span></Link>
          </article>

          <article className="surface-card profile-card">
            <div className="card-heading"><span className="round-icon blue-icon" aria-hidden="true">◎</span><span className="card-label">PROFIL</span></div>
            <h3>Informations du compte</h3>
            <dl className="profile-details">
              <div><dt>Nom d’utilisateur</dt><dd>{user?.username || '—'}</dd></div>
              <div><dt>Adresse e-mail</dt><dd>{user?.email || '—'}</dd></div>
              <div><dt>Type de compte</dt><dd>{user?.role || 'Utilisateur'}</dd></div>
            </dl>
          </article>

          <article className="surface-card actions-card">
            <div className="card-heading"><span className="round-icon violet-icon" aria-hidden="true">↗</span><span className="card-label">RACCOURCIS</span></div>
            <h3>Actions rapides</h3>
            <Link className="action-row" to="/account/password">
              <span className="action-symbol" aria-hidden="true">⌑</span>
              <span><strong>Changer le mot de passe</strong><small>Mettez à jour votre accès</small></span>
              <span className="action-arrow" aria-hidden="true">→</span>
            </Link>
            <Link className="action-row" to="/account/mfa">
              <span className="action-symbol" aria-hidden="true">◇</span>
              <span><strong>Gérer la double authentification</strong><small>Application et codes de secours</small></span>
              <span className="action-arrow" aria-hidden="true">→</span>
            </Link>
          </article>
        </section>

        <aside className="security-note">
          <span className="note-icon" aria-hidden="true">i</span>
          <p><strong>Conseil de sécurité</strong><br/>Ne partagez jamais vos codes de vérification. SecureAuth ne vous demandera jamais votre mot de passe par e-mail.</p>
          <Link to="/account/mfa">Voir mes options de sécurité</Link>
        </aside>
        {error && <FormError>{error}</FormError>}
        <footer className="dashboard-footer">
          <span>SecureAuth</span><span>Votre compte, protégé à chaque étape.</span>
          <button className="footer-logout" onClick={signOut} disabled={busy}>Se déconnecter</button>
        </footer>
      </main>
    </div>
  );
}

export function ChangePassword() {
  const schema = z.object({ current_password: z.string().min(1, 'Mot de passe actuel requis.'), new_password: password, confirmation: z.string() }).refine((values) => values.new_password === values.confirmation, { path: ['confirmation'], message: 'Les nouveaux mots de passe ne correspondent pas.' });
  const { register, handleSubmit, formState: { errors, isSubmitting }, reset } = useForm<{ current_password: string; new_password: string; confirmation: string }>({ resolver: zodResolver(schema) });
  const [message, setMessage] = useState(''); const [error, setError] = useState('');
  const submit = handleSubmit(async ({ current_password, new_password }) => { setMessage(''); setError(''); try { const result = await api.changePassword({ current_password, new_password }); setMessage(result.message ?? 'Mot de passe modifié.'); reset(); } catch (e) { setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'Le changement a échoué.'); } });
  return <Shell title="Changer le mot de passe"><form onSubmit={submit} noValidate><PasswordField id="current_password" name="current_password" label="Mot de passe actuel" autoComplete="current-password" register={register('current_password')} /><PasswordField id="new_password" name="new_password" label="Nouveau mot de passe" autoComplete="new-password" register={register('new_password')} /><PasswordField id="confirmation" name="confirmation" label="Confirmer le nouveau mot de passe" autoComplete="new-password" register={register('confirmation')} />{formErrors(errors) && <FormError>{formErrors(errors)}</FormError>}{error && <FormError>{error}</FormError>}{message && <p role="status">{message}</p>}<button disabled={isSubmitting}>{isSubmitting ? 'Modification…' : 'Modifier le mot de passe'}</button></form></Shell>;
}

export function EnrollMfa() {
  const auth = useAuth(); const navigate = useNavigate(); const [enrollment, setEnrollment] = useState<{ secret: string; qr_code_uri: string; recovery_codes: string[] } | null>(null);
  const [acknowledged, setAcknowledged] = useState(false); const [message, setMessage] = useState(''); const [error, setError] = useState('');
  const enrollForm = useForm<{ totp_code: string }>();
  async function startEnrollment() { setError(''); setMessage(''); try { const result = await api.startMfaEnrollment(); setEnrollment(result); setAcknowledged(false); enrollForm.reset(); } catch (e) { setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'Impossible de démarrer la MFA.'); } }
  const confirmEnrollment = enrollForm.handleSubmit(async ({ totp_code }) => { setError(''); try { const result = await api.confirmMfaEnrollment(totp_code); if (result.reauthentication_required) { auth.clear(); navigate('/login', { replace: true }); return; } if (result.success) { auth.updateUser({ mfa_enabled: true, mfa_enrollment_required: false }); setEnrollment(null); setMessage('Double authentification activée et obligatoire. Conservez vos codes de récupération en lieu sûr.'); enrollForm.reset(); } } catch (e) { setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'Le code MFA n’a pas pu être vérifié.'); } });
  return (
    <Shell title="Authentification multifacteur">
      {auth.user?.mfa_enabled ? <>
        <p>La double authentification est activée et obligatoire sur votre compte.</p>
        <p>Vous devrez saisir un code de votre application d’authentification à chaque connexion.</p>
      </> : enrollment ? <>
        <p><strong>Le QR ne montre pas les 6 chiffres.</strong> Ouvrez votre application d’authentification, choisissez « Ajouter un compte » puis « Scanner un QR code ». Ne le scannez pas avec l’appareil photo classique : le long texte affiché par un lecteur QR est la configuration, pas le code de validation.</p>
        <p>Une fois le compte ajouté, l’application affichera un code temporaire à 6 chiffres, renouvelé toutes les 30 secondes. Saisissez ces 6 chiffres dans le champ ci-dessous.</p>
        <section className="enrollment">
          <QRCodeSVG value={enrollment.qr_code_uri} aria-label="QR code d'enrôlement TOTP" />
          <details>
            <summary>Le QR ne peut pas être scanné ? Saisie manuelle</summary>
            <p>Dans l’application d’authentification, choisissez « Saisir une clé de configuration » et copiez cette clé. Elle sert à configurer l’application; ne la saisissez pas dans le champ du code à 6 chiffres.</p>
            <p>Clé de configuration : <code>{enrollment.secret}</code></p>
          </details>
          <h2>Codes de récupération</h2>
          <p>Enregistrez ces codes en lieu sûr. Ils ne seront plus affichés après avoir quitté cette page.</p>
          <ul>{enrollment.recovery_codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul>
          <label><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /> J’ai conservé mes codes de récupération</label>
        </section>
        <form onSubmit={confirmEnrollment} noValidate>
          <div className="field"><label htmlFor="totp_code">Code TOTP à 6 chiffres</label><input id="totp_code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} {...enrollForm.register('totp_code', { required: true })} /></div>
          <button disabled={!acknowledged || enrollForm.formState.isSubmitting}>{enrollForm.formState.isSubmitting ? 'Vérification…' : 'Confirmer et activer la MFA'}</button>
        </form>
      </> : <>
        <p>La double authentification est obligatoire. Configurez-la maintenant pour accéder au compte.</p>
        <button onClick={startEnrollment}>Configurer la MFA</button>
      </>}
      {error && <FormError>{error}</FormError>}
      {message && <p role="status">{message}</p>}
    </Shell>
  );
}

export function ForgotPassword() {
  const { register, handleSubmit, formState: { errors, isSubmitting }, reset } = useForm<{ identifier: string }>({
    resolver: zodResolver(z.object({
      identifier: z.string().trim().min(1, 'Saisissez votre adresse e-mail ou votre nom d’utilisateur.'),
    })),
  });
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const submit = handleSubmit(async ({ identifier }) => {
    setError('');
    setMessage('');
    try {
      const result = await api.requestPasswordReset({ identifier });
      setMessage(result.message ?? 'Si le compte existe, les instructions ont été envoyées. Vérifiez aussi vos courriers indésirables.');
      reset();
    } catch (e) {
      setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'Le service est momentanément indisponible.');
    }
  });

  return (
    <Shell title="Réinitialiser votre mot de passe">
      <p className="form-lead">Indiquez l’adresse e-mail ou le nom d’utilisateur associé à votre compte. Nous vous enverrons un lien sécurisé s’il existe.</p>
      <div className="info-banner"><span aria-hidden="true">✉</span><p>Le lien est à usage unique et expire après 20 minutes. Pensez à vérifier vos courriers indésirables.</p></div>
      <form onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="identifier">Adresse e-mail ou nom d’utilisateur</label>
          <input id="identifier" type="text" autoComplete="username" placeholder="vous@exemple.com" {...register('identifier')} />
        </div>
        {formErrors(errors) && <FormError>{formErrors(errors)}</FormError>}
        {error && <FormError>{error}</FormError>}
        {message && <p className="success-message" role="status" aria-live="polite"><span aria-hidden="true">✓</span>{message}</p>}
        <button className="primary-button" disabled={isSubmitting}>{isSubmitting ? 'Envoi en cours…' : 'Envoyer le lien de réinitialisation'}</button>
      </form>
      <p className="form-footnote">Vous n’avez pas reçu d’e-mail ? L’envoi nécessite une messagerie configurée par l’administrateur de la plateforme.</p>
      {import.meta.env.DEV && <p className="dev-mail-note">En mode local, le message de test est ici : <a href="http://127.0.0.1:8025" target="_blank" rel="noreferrer">ouvrir la boîte Mailpit</a>.</p>}
      <Link className="back-link" to="/login"><span aria-hidden="true">←</span> Retour à la connexion</Link>
    </Shell>
  );
}

export function ResetPassword() {
  const [token] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const value = params.get('token') ?? '';
    window.history.replaceState({}, '', window.location.pathname);
    return value;
  });
  const [factor, setFactor] = useState<'totp' | 'recovery'>('totp');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [passwordFeedback, setPasswordFeedback] = useState<string[]>([]);
  const schema = z.object({
    new_password: password,
    confirmation: z.string(),
    totp_code: z.string().optional(),
    recovery_code: z.string().optional(),
  }).refine((values) => values.new_password === values.confirmation, {
    path: ['confirmation'],
    message: 'Les mots de passe ne correspondent pas.',
  });
  const { register, handleSubmit, formState: { errors, isSubmitting }, reset } = useForm<ResetFields>({ resolver: zodResolver(schema) });

  const submit = handleSubmit(async (values) => {
    setError('');
    setMessage('');
    try {
      const result = await api.completePasswordReset({
        token,
        new_password: values.new_password,
        ...(factor === 'totp' ? { totp_code: values.totp_code } : { recovery_code: values.recovery_code }),
      });
      setMessage(result.message ?? 'Mot de passe réinitialisé. Veuillez vous reconnecter.');
      reset();
    } catch (e) {
      setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'La réinitialisation a échoué.');
    }
  });

  const newPasswordField = register('new_password');
  const validateNewPassword = async (event: Parameters<typeof newPasswordField.onBlur>[0]) => {
    await newPasswordField.onBlur(event);
    const value = (event.target as HTMLInputElement).value;
    if (value.length < PASSWORD_MIN_LENGTH || value.length > PASSWORD_MAX_LENGTH) return;
    try {
      const result = await api.validatePassword(value);
      setPasswordFeedback(result.errors);
    } catch (e) {
      setPasswordFeedback([e instanceof Error ? e.message : 'Validation indisponible.']);
    }
  };

  return (
    <Shell title="Choisir un nouveau mot de passe">
      <p className="form-lead">Créez une phrase de passe de 12 à 128 caractères. Elle doit être différente de votre ancien mot de passe.</p>
      {token ? (
        <form onSubmit={submit} noValidate>
          <PasswordField id="new_password" name="new_password" label="Nouveau mot de passe" autoComplete="new-password" register={{ ...newPasswordField, onBlur: validateNewPassword }} />
          <PasswordField id="confirmation" name="confirmation" label="Confirmer le nouveau mot de passe" autoComplete="new-password" register={register('confirmation')} />
          {passwordFeedback.length > 0 && <ul className="password-feedback" aria-live="polite">{passwordFeedback.map((item) => <li key={item}>{item}</li>)}</ul>}
          <div className="factor-heading"><span>Vérification de sécurité</span><small>Requise si la MFA est activée</small></div>
          {factor === 'totp' ? (
            <div className="field"><label htmlFor="totp_code">Code à 6 chiffres</label><input id="totp_code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" {...register('totp_code')} /></div>
          ) : (
            <div className="field"><label htmlFor="recovery_code">Code de récupération</label><input id="recovery_code" autoComplete="off" placeholder="Code à usage unique" {...register('recovery_code')} /></div>
          )}
          <button type="button" className="factor-switch" onClick={() => setFactor(factor === 'totp' ? 'recovery' : 'totp')}>Utiliser {factor === 'totp' ? 'un code de récupération' : 'un code d’authentification'}</button>
          {formErrors(errors) && <FormError>{formErrors(errors)}</FormError>}
          {error && <FormError>{error}</FormError>}
          {message && <p className="success-message" role="status">{message}</p>}
          <button className="primary-button" disabled={isSubmitting}>{isSubmitting ? 'Mise à jour…' : 'Enregistrer le nouveau mot de passe'}</button>
        </form>
      ) : (
        <div className="info-banner error-banner"><span aria-hidden="true">!</span><p>Ce lien est incomplet ou a déjà été retiré de l’adresse. Demandez un nouveau lien de réinitialisation.</p></div>
      )}
      {!message && !token && <Link className="back-link" to="/password-reset"><span aria-hidden="true">←</span> Demander un nouveau lien</Link>}
    </Shell>
  );
}

export function MfaRecovery() {
  const { register, handleSubmit, formState: { isSubmitting } } = useForm<{ identifier: string }>(); const [message, setMessage] = useState(''); const [error, setError] = useState('');
  const submit = handleSubmit(async ({ identifier }) => { setError(''); setMessage(''); try { const result = await api.requestMfaRecovery(identifier); setMessage(result.message ?? 'Si le compte peut être récupéré, les instructions ont été envoyées.'); } catch (e) { setError(e instanceof Error ? e.message : 'La demande a échoué.'); } });
  return <Shell title="Récupération MFA"><p>Indiquez votre nom d'utilisateur ou votre adresse e-mail. Si le compte existe et peut être récupéré, un lien sera envoyé.</p><form onSubmit={submit} noValidate><div className="field"><label htmlFor="identifier">Nom d'utilisateur ou adresse e-mail</label><input id="identifier" autoComplete="username" {...register('identifier', { required: true })} /></div>{error && <FormError>{error}</FormError>}{message && <p role="status">{message}</p>}<button disabled={isSubmitting}>{isSubmitting ? 'Envoi…' : 'Envoyer un lien de récupération'}</button></form></Shell>;
}

export function MfaRecoveryConfirm() {
  const navigate = useNavigate(); const auth = useAuth();
  const [token] = useState(() => { const value = new URLSearchParams(window.location.search).get('token') ?? ''; window.history.replaceState({}, '', window.location.pathname); return value; });
  const { register, handleSubmit, formState: { isSubmitting } } = useForm<{ current_password: string }>(); const [error, setError] = useState(''); const [message, setMessage] = useState('');
  const submit = handleSubmit(async ({ current_password }) => { setError(''); try { const result = await api.completeMfaRecovery({ token, current_password }); setMessage(result.message ?? 'MFA réinitialisé.'); auth.clear(); navigate('/login', { replace: true }); } catch (e) { setError(e instanceof ApiException ? e.payload?.errors?.[0] ?? e.message : 'La récupération a échoué.'); } });
  return <Shell title="Confirmer la récupération MFA"><form onSubmit={submit} noValidate><PasswordField id="current_password" name="current_password" label="Mot de passe actuel" autoComplete="current-password" register={register('current_password', { required: true })} />{error && <FormError>{error}</FormError>}{message && <p role="status">{message}</p>}<button disabled={isSubmitting || !token}>{isSubmitting ? 'Validation…' : 'Réinitialiser la MFA'}</button></form>{!token && <FormError>Le lien de récupération est invalide ou incomplet.</FormError>}</Shell>;
}

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const location = useLocation(); const { authenticated, loading, setMessage, user } = useAuth();
  useEffect(() => { if (!authenticated && !loading) setMessage('Connectez-vous pour accéder à cette page.'); }, [authenticated, loading, setMessage]);
  if (loading) return <main className="card" role="status">Vérification de la session…</main>;
  if (authenticated && user?.mfa_enrollment_required && location.pathname !== '/account/mfa') return <Navigate to="/account/mfa" replace />;
  return authenticated ? <>{children}</> : <Navigate to="/login" replace state={{ from: location.pathname }} />;
}
