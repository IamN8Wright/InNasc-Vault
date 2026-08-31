'use client';

import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import {
  Activity,
  AlertTriangle,
  Building2,
  Check,
  ChevronRight,
  Clipboard,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileJson,
  Globe2,
  HardDrive,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  MapPin,
  MonitorCog,
  Network,
  Pencil,
  Phone,
  Plus,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  ShieldX,
  Smartphone,
  Trash2,
  UserCog,
  Users,
  Wifi,
  X,
} from 'lucide-react';
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { ApiError, api, downloadFromApi } from '@/lib/api';

type Role = 'workspace_owner' | 'admin' | 'technician' | 'client_admin' | 'client_user' | 'read_only';
type Collection = 'network' | 'av_systems' | 'voip' | 'access_control' | 'remote_access' | 'software' | 'websites_accounts' | 'general';
type Page = 'dashboard' | 'clients' | 'vault' | 'assets' | 'users' | 'audit' | 'settings';

type User = {
  id: string;
  name: string;
  email: string;
  role: Role;
  mfaEnabled: boolean;
  recoveryCodesRemaining: number;
  passkeyCount: number;
  lastLoginAt: string | null;
};

type Session = {
  user: User;
  csrfToken: string;
  expiresAt: string;
  stepUpUntil: string | null;
  capabilities?: { passkeys: boolean; sqliteBackup: boolean };
};

type LoginChallenge = {
  challengeId: string;
  kind: 'login' | 'enrollment';
  qrCodeDataUrl?: string;
  manualKey?: string;
  passkeyAvailable: boolean;
};

type Client = { id: string; name: string; code: string; notes: string; updated_at: string };
type Location = { id: string; client_id: string; name: string; address: string; notes: string };
type SystemRecord = { id: string; client_id: string; location_id: string; name: string; collection: Collection; manufacturer: string; model: string; network_address: string; notes: string };
type Credential = { id: string; client_id: string; location_id: string; system_id: string | null; collection: Collection; name: string; url: string; client_name: string; location_name: string; system_name: string | null; last_verified_at: string | null; expires_at: string | null; updated_at: string };
type Asset = { id: string; client_id: string; location_id: string; system_id: string | null; asset_type: 'device' | 'software' | 'website_account'; name: string; vendor: string; version_or_model: string; identifier: string; url: string; notes: string; client_name: string; location_name: string; system_name: string | null };
type AuditEntry = { id: string; occurred_at: string; actor_name: string | null; event_type: string; target_type: string | null; outcome: string; detail_json: string };
type Dashboard = { clients: number; locations: number; systems: number; credentials: number; recentClients: Client[] };
type Secret = { username: string; password: string; pin: string; apiToken: string; licenseKey: string; notes: string };

const collectionLabels: Record<Collection, string> = {
  network: 'Network',
  av_systems: 'AV systems',
  voip: 'VoIP',
  access_control: 'Access control',
  remote_access: 'Remote access',
  software: 'Software',
  websites_accounts: 'Websites & accounts',
  general: 'General',
};

const roleLabels: Record<Role, string> = {
  workspace_owner: 'Workspace Owner',
  admin: 'Admin',
  technician: 'Technician',
  client_admin: 'Client Admin',
  client_user: 'Client User',
  read_only: 'Read Only',
};

const nav: Array<{ page: Page; label: string; icon: typeof LayoutDashboard }> = [
  { page: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { page: 'clients', label: 'Clients', icon: Building2 },
  { page: 'vault', label: 'Credential vault', icon: KeyRound },
  { page: 'assets', label: 'Devices & software', icon: HardDrive },
  { page: 'users', label: 'Users & permissions', icon: Users },
  { page: 'audit', label: 'Audit log', icon: Activity },
  { page: 'settings', label: 'Security & backup', icon: Settings },
];

function initials(name: string) {
  return name.split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase();
}

function dateTime(value?: string | null) {
  if (!value) return 'Never';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

function securePassword(length = 24) {
  const groups = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*()-_=+'];
  const alphabet = groups.join('');
  const randomIndex = (max: number) => {
    const ceiling = Math.floor(256 / max) * max;
    const byte = new Uint8Array(1);
    do crypto.getRandomValues(byte); while (byte[0] >= ceiling);
    return byte[0] % max;
  };
  const characters = groups.map((group) => group[randomIndex(group.length)]);
  while (characters.length < length) characters.push(alphabet[randomIndex(alphabet.length)]);
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swap = randomIndex(index + 1);
    [characters[index], characters[swap]] = [characters[swap], characters[index]];
  }
  return characters.join('');
}

function messageFrom(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong.';
}

export default function VaultApp() {
  const [booting, setBooting] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);
  const [setupIncomplete, setSetupIncomplete] = useState(false);
  const [setupTokenRequired, setSetupTokenRequired] = useState(false);
  const [session, setSession] = useState<Session | null>(null);
  const [offline, setOffline] = useState(false);

  const boot = useCallback(async () => {
    setBooting(true);
    setOffline(false);
    try {
      const status = await api<{ setupRequired: boolean; setupIncomplete?: boolean; setupTokenRequired?: boolean }>('/setup/status');
      setSetupRequired(status.setupRequired);
      setSetupIncomplete(Boolean(status.setupIncomplete));
      setSetupTokenRequired(Boolean(status.setupTokenRequired));
      if (!status.setupRequired) {
        try {
          setSession(await api<Session>('/session'));
        } catch (error) {
          if (!(error instanceof ApiError) || error.status !== 401) throw error;
          setSession(null);
        }
      }
    } catch (error) {
      setOffline(error instanceof ApiError && error.code === 'SERVICE_OFFLINE');
    } finally {
      setBooting(false);
    }
  }, []);

  useEffect(() => { void boot(); }, [boot]);

  if (booting) return <LoadingScreen />;
  if (offline) return <OfflineScreen onRetry={boot} />;
  if (!session) {
    return (
      <AuthScreen
        setupRequired={setupRequired}
        setupIncomplete={setupIncomplete}
        setupTokenRequired={setupTokenRequired}
        onAuthenticated={(next) => {
          setSession(next);
          setSetupRequired(false);
          setSetupIncomplete(false);
        }}
      />
    );
  }
  return <Workspace session={session} setSession={setSession} />;
}

function Brand() {
  return (
    <div className="brand-lockup">
      <img className="brand-mark" src="/innasc-vault-mark.png" alt="" aria-hidden="true" />
      <span><strong>InNasc</strong><small>VAULT</small></span>
    </div>
  );
}

function LoadingScreen() {
  return <main className="auth-shell"><div className="auth-card loading-card"><Brand /><RefreshCw className="spin" /><p>Opening the encrypted local workspace…</p></div></main>;
}

function OfflineScreen({ onRetry }: { onRetry: () => void }) {
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <Brand />
        <span className="auth-icon danger"><ShieldX /></span>
        <p className="eyebrow">LOCAL SERVICE OFFLINE</p>
        <h1>InNasc Vault is not running</h1>
        <p className="auth-copy">Double-click <strong>Start-InNasc-Vault.cmd</strong>, leave the black window open, then retry.</p>
        <Button size="lg" onClick={onRetry}><RefreshCw /> Retry connection</Button>
      </section>
    </main>
  );
}

function AuthScreen({ setupRequired, setupIncomplete, setupTokenRequired, onAuthenticated }: { setupRequired: boolean; setupIncomplete: boolean; setupTokenRequired: boolean; onAuthenticated: (session: Session) => void }) {
  const [stage, setStage] = useState<'credentials' | 'mfa' | 'recovery'>(setupRequired ? 'credentials' : 'credentials');
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [newSession, setNewSession] = useState<Session | null>(null);
  const [savedCodes, setSavedCodes] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submitCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const body = setupRequired
        ? { name: form.get('name'), email: form.get('email'), password: form.get('password'), setupToken: form.get('setupToken') }
        : { email: form.get('email'), password: form.get('password') };
      const next = await api<LoginChallenge>(setupRequired ? '/setup/start' : '/auth/login', { method: 'POST', body: JSON.stringify(body) });
      setChallenge(next);
      setStage('mfa');
    } catch (nextError) {
      setError(messageFrom(nextError));
    } finally {
      setBusy(false);
    }
  }

  async function submitMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!challenge) return;
    setError('');
    setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<Session & { recoveryCodes?: string[] }>('/auth/mfa/verify', {
        method: 'POST',
        body: JSON.stringify({ challengeId: challenge.challengeId, code: form.get('code') }),
      });
      if (result.recoveryCodes?.length) {
        setRecoveryCodes(result.recoveryCodes);
        setNewSession(result);
        setStage('recovery');
      } else {
        onAuthenticated(result);
      }
    } catch (nextError) {
      setError(messageFrom(nextError));
    } finally {
      setBusy(false);
    }
  }

  async function signInWithPasskey() {
    if (!challenge) return;
    setError('');
    setBusy(true);
    try {
      const options = await api<{ challengeId: string; options: Parameters<typeof startAuthentication>[0]['optionsJSON'] }>('/auth/passkey/options', {
        method: 'POST', body: JSON.stringify({ loginChallengeId: challenge.challengeId }),
      });
      const credential = await startAuthentication({ optionsJSON: options.options });
      const result = await api<Session>('/auth/passkey/verify', {
        method: 'POST', body: JSON.stringify({ challengeId: options.challengeId, response: credential }),
      });
      onAuthenticated(result);
    } catch (nextError) {
      setError(messageFrom(nextError));
    } finally {
      setBusy(false);
    }
  }

  if (stage === 'recovery' && newSession) {
    return (
      <main className="auth-shell">
        <section className="auth-card auth-card-wide">
          <Brand />
          <span className="auth-icon"><ShieldCheck /></span>
          <p className="eyebrow">ONE-TIME DISPLAY</p>
          <h1>Save your recovery codes</h1>
          <p className="auth-copy">Each code can be used once if your authenticator is unavailable. They cannot be shown again.</p>
          <div className="recovery-grid">{recoveryCodes.map((code) => <code key={code}>{code}</code>)}</div>
          <Button variant="outline" onClick={() => navigator.clipboard.writeText(recoveryCodes.join('\n'))}><Copy /> Copy all codes</Button>
          <label className="check-row"><input type="checkbox" checked={savedCodes} onChange={(event) => setSavedCodes(event.target.checked)} /> I saved these codes somewhere secure.</label>
          <Button size="lg" disabled={!savedCodes} onClick={() => onAuthenticated(newSession)}>Enter InNasc Vault <ChevronRight /></Button>
        </section>
      </main>
    );
  }

  return (
    <main className="auth-shell">
      <section className={`auth-card ${challenge?.kind === 'enrollment' ? 'auth-card-wide' : ''}`}>
        <Brand />
        {stage === 'credentials' ? (
          <>
            <span className="auth-icon"><LockKeyhole /></span>
            <p className="eyebrow">{setupIncomplete ? 'RESUME SETUP' : setupRequired ? 'FIRST-RUN SETUP' : 'SECURE LOCAL WORKSPACE'}</p>
            <h1>{setupIncomplete ? 'Resume workspace owner setup' : setupRequired ? 'Create the workspace owner' : 'Welcome back'}</h1>
            <p className="auth-copy">{setupIncomplete ? 'The earlier enrollment did not finish. Re-enter the owner details to create a fresh MFA enrollment.' : setupRequired ? 'Your password unlocks the local encryption key. MFA enrollment is required before the vault opens.' : 'Enter your password, then confirm with your authenticator or passkey.'}</p>
            <form className="auth-form" onSubmit={submitCredentials}>
              {setupRequired && <label>Full name<Input name="name" autoComplete="name" required minLength={2} /></label>}
              {setupRequired && setupTokenRequired && <label>Deployment setup key<Input name="setupToken" type="password" autoComplete="off" required /></label>}
              <label>Email address<Input name="email" type="email" autoComplete="username" required /></label>
              <label>Password<Input name="password" type="password" autoComplete={setupRequired ? 'new-password' : 'current-password'} required minLength={setupRequired ? 14 : 1} /></label>
              {setupRequired && <p className="field-hint">At least 14 characters with uppercase, lowercase, number, and symbol.</p>}
              {error && <Alert variant="destructive"><AlertTriangle /><AlertTitle>Couldn’t continue</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
              <Button size="lg" type="submit" disabled={busy}>{busy ? <RefreshCw className="spin" /> : <ShieldCheck />} {setupIncomplete ? 'Resume secure setup' : setupRequired ? 'Create secure workspace' : 'Continue to MFA'}</Button>
            </form>
          </>
        ) : (
          <>
            <span className="auth-icon"><Smartphone /></span>
            <p className="eyebrow">MULTI-FACTOR AUTHENTICATION</p>
            <h1>{challenge?.kind === 'enrollment' ? 'Connect your authenticator' : 'Confirm it’s you'}</h1>
            <p className="auth-copy">{challenge?.kind === 'enrollment' ? 'Scan this code with Microsoft Authenticator, Google Authenticator, 1Password, or another TOTP app.' : 'Enter the current six-digit code. A one-time recovery code also works.'}</p>
            {challenge?.qrCodeDataUrl && <div className="qr-wrap"><img src={challenge.qrCodeDataUrl} alt="Authenticator enrollment QR code" /><code>{challenge.manualKey}</code></div>}
            <form className="auth-form" onSubmit={submitMfa}>
              <label>{challenge?.kind === 'enrollment' ? 'Six-digit code' : 'Authenticator or recovery code'}<Input name="code" inputMode="numeric" autoComplete="one-time-code" required /></label>
              {error && <Alert variant="destructive"><AlertTriangle /><AlertDescription>{error}</AlertDescription></Alert>}
              <Button size="lg" type="submit" disabled={busy}>{busy ? <RefreshCw className="spin" /> : <ShieldCheck />} Verify and continue</Button>
              {challenge?.passkeyAvailable && <Button type="button" variant="outline" onClick={signInWithPasskey} disabled={busy}><KeyRound /> Use a passkey instead</Button>}
            </form>
          </>
        )}
      </section>
      <p className="auth-footnote">{window.location.hostname === 'localhost' ? 'Local alpha · encrypted SQLite storage' : 'Hosted beta · encrypted cloud storage'}</p>
    </main>
  );
}

function Workspace({ session, setSession }: { session: Session; setSession: (session: Session | null) => void }) {
  const [page, setPage] = useState<Page>('dashboard');
  const [data, setData] = useState<{
    dashboard: Dashboard;
    clients: Client[];
    locations: Location[];
    systems: SystemRecord[];
    credentials: Credential[];
    assets: Asset[];
    users: User[];
    audit: AuditEntry[];
  }>({ dashboard: { clients: 0, locations: 0, systems: 0, credentials: 0, recentClients: [] }, clients: [], locations: [], systems: [], credentials: [], assets: [], users: [], audit: [] });
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingSecureAction = useRef<null | (() => Promise<void>)>(null);
  const admin = session.user.role === 'workspace_owner' || session.user.role === 'admin';

  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const requests: Promise<unknown>[] = [
        api<Dashboard>('/dashboard'), api<Client[]>('/clients'), api<Location[]>('/locations'),
        api<SystemRecord[]>('/systems'), api<Credential[]>('/credentials'), api<Asset[]>('/assets'), api<AuditEntry[]>('/audit'),
      ];
      if (admin) requests.push(api<User[]>('/users'));
      const [dashboard, clients, locations, systems, credentials, assets, auditRows, users = []] = await Promise.all(requests);
      setData({ dashboard, clients, locations, systems, credentials, assets, audit: auditRows, users } as typeof data);
    } catch (nextError) {
      if (nextError instanceof ApiError && nextError.status === 401) setSession(null);
      else setError(messageFrom(nextError));
    } finally {
      setLoading(false);
    }
  }, [admin, setSession]);

  useEffect(() => { void refresh(); }, [refresh]);

  const secure = useCallback(async (action: () => Promise<void>) => {
    try {
      await action();
    } catch (nextError) {
      if (nextError instanceof ApiError && nextError.code === 'STEP_UP_REQUIRED') {
        pendingSecureAction.current = action;
        setStepUpOpen(true);
      } else {
        setError(messageFrom(nextError));
      }
    }
  }, []);

  async function signOut() {
    try { await api('/auth/logout', { method: 'POST', csrfToken: session.csrfToken }); } finally { setSession(null); }
  }

  function showNotice(value: string) {
    setNotice(value);
    window.setTimeout(() => setNotice(''), 3500);
  }

  const title = nav.find((item) => item.page === page)?.label ?? 'Dashboard';

  return (
    <main className="vault-shell">
      <aside className="vault-sidebar">
        <Brand />
        <nav aria-label="Primary navigation" className="vault-nav">
          <p>Workspace</p>
          {nav.filter((item) => item.page !== 'users' || admin).map(({ page: itemPage, label, icon: Icon }) => (
            <button className={page === itemPage ? 'active' : ''} key={itemPage} type="button" onClick={() => setPage(itemPage)}>
              <Icon aria-hidden="true" /><span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="security-status"><ShieldCheck /><div><strong>Local vault</strong><span>Encrypted & MFA protected</span></div></div>
      </aside>

      <section className="vault-workspace">
        <header className="topbar">
          <div><span className="eyebrow">LOCAL WORKSPACE</span><h1>{title}</h1></div>
          <div className="topbar-actions">
            <Badge variant="outline" className="status-badge"><span className="status-dot" /> {window.location.hostname === 'localhost' ? 'localhost' : 'hosted beta'}</Badge>
            <button className="user-chip" type="button" onClick={() => setPage('settings')}><span>{initials(session.user.name)}</span><span><strong>{session.user.name}</strong><small>{roleLabels[session.user.role]}</small></span></button>
          </div>
        </header>

        <div className="workspace-scroll">
          {notice && <div className="toast-notice"><Check /> {notice}</div>}
          {error && <Alert variant="destructive" className="page-alert"><AlertTriangle /><AlertTitle>Action needed</AlertTitle><AlertDescription>{error}</AlertDescription><button onClick={() => setError('')} aria-label="Dismiss"><X /></button></Alert>}
          {loading ? <PageLoading /> : (
            <PageContent
              page={page}
              session={session}
              data={data}
              refresh={refresh}
              secure={secure}
              showNotice={showNotice}
              setError={setError}
              setSession={setSession}
              signOut={signOut}
            />
          )}
        </div>
      </section>

      <StepUpDialog
        open={stepUpOpen}
        setOpen={setStepUpOpen}
        session={session}
        onVerified={async (stepUpUntil) => {
          setSession({ ...session, stepUpUntil });
          setStepUpOpen(false);
          const action = pendingSecureAction.current;
          pendingSecureAction.current = null;
          if (action) await secure(action);
        }}
      />
    </main>
  );
}

function PageLoading() {
  return <div className="page-loading"><RefreshCw className="spin" /><span>Loading secure workspace…</span></div>;
}

type PageProps = {
  page: Page;
  session: Session;
  data: { dashboard: Dashboard; clients: Client[]; locations: Location[]; systems: SystemRecord[]; credentials: Credential[]; assets: Asset[]; users: User[]; audit: AuditEntry[] };
  refresh: () => Promise<void>;
  secure: (action: () => Promise<void>) => Promise<void>;
  showNotice: (message: string) => void;
  setError: (message: string) => void;
  setSession: (session: Session | null) => void;
  signOut: () => Promise<void>;
};

function PageContent(props: PageProps) {
  switch (props.page) {
    case 'clients': return <ClientsPage {...props} />;
    case 'vault': return <VaultPage {...props} />;
    case 'assets': return <AssetsPage {...props} />;
    case 'users': return <UsersPage {...props} />;
    case 'audit': return <AuditPage {...props} />;
    case 'settings': return <SettingsPage {...props} />;
    default: return <DashboardPage {...props} />;
  }
}

function PageHeader({ eyebrow, title, copy, action }: { eyebrow: string; title: string; copy: string; action?: React.ReactNode }) {
  return (
    <header className="page-heading">
      <div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2><p>{copy}</p></div>
      {action}
    </header>
  );
}

function EmptyState({ icon: Icon, title, copy, action }: { icon: typeof Building2; title: string; copy: string; action?: React.ReactNode }) {
  return <div className="empty-state"><span><Icon /></span><strong>{title}</strong><p>{copy}</p>{action}</div>;
}

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return <label className="form-field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}

function SelectField({ name, label, value, onChange, children, required = false, disabled = false }: { name: string; label: string; value?: string; onChange?: (value: string) => void; children: React.ReactNode; required?: boolean; disabled?: boolean }) {
  return <Field label={label}><select name={name} value={value} onChange={(event) => onChange?.(event.target.value)} required={required} disabled={disabled}>{children}</select></Field>;
}

function DashboardPage({ data, session, setError }: PageProps) {
  const stats = [
    { label: 'Clients', value: data.dashboard.clients, icon: Building2 },
    { label: 'Locations', value: data.dashboard.locations, icon: MapPin },
    { label: 'Systems', value: data.dashboard.systems, icon: HardDrive },
    { label: 'Credentials', value: data.dashboard.credentials, icon: KeyRound },
  ];
  return (
    <>
      <section className="welcome-row">
        <div><p className="eyebrow">SYSTEMS IN CONTEXT.</p><h2>Good {new Date().getHours() < 12 ? 'morning' : new Date().getHours() < 18 ? 'afternoon' : 'evening'}, {session.user.name.split(' ')[0]}</h2><p>Your client technology records and encrypted credentials stay together in one local workspace.</p></div>
        <div className="security-pill"><ShieldCheck /><span><strong>MFA enforced</strong><small>Step-up required for secrets</small></span></div>
      </section>
      <section className="stat-grid">
        {stats.map(({ label, value, icon: Icon }) => <article className="stat-card" key={label}><span className="stat-icon"><Icon /></span><span><small>{label}</small><strong>{value}</strong></span></article>)}
      </section>
      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-heading"><div><span className="eyebrow">CLIENTS</span><h3>Recently opened</h3></div><Building2 /></div>
          {data.dashboard.recentClients.length ? <div className="client-list">{data.dashboard.recentClients.map((client) => <div key={client.id}><span className="list-icon"><Building2 /></span><span><strong>{client.name}</strong><small>{client.code || 'No client code'} · Updated {dateTime(client.updated_at)}</small></span><ChevronRight /></div>)}</div> : <EmptyState icon={Building2} title="No clients yet" copy="Add your first real client from the Clients page. No sample secrets are included." />}
        </article>
        <article className="panel security-panel">
          <div className="panel-heading"><div><span className="eyebrow">SECURITY POSTURE</span><h3>Local protection</h3></div><ShieldCheck /></div>
          <ul className="security-checklist">
            <li><Check /><span><strong>Vault encryption</strong><small>XChaCha20-Poly1305 authenticated encryption</small></span></li>
            <li><Check /><span><strong>Password hardening</strong><small>Argon2id with a per-user salt</small></span></li>
            <li><Check /><span><strong>MFA & recovery</strong><small>Authenticator app required from first login</small></span></li>
            <li><Check /><span><strong>Local-only binding</strong><small>Backend listens only on this PC</small></span></li>
          </ul>
          <Button variant="outline" onClick={() => setError('Temporary sharing remains intentionally disabled in the local build.')}><ShieldCheck /> Local trial safety note</Button>
        </article>
      </section>
    </>
  );
}

function ClientsPage({ data, session, refresh, showNotice, setError }: PageProps) {
  const [clientOpen, setClientOpen] = useState(false);
  const [locationOpen, setLocationOpen] = useState(false);
  const [systemOpen, setSystemOpen] = useState(false);
  const [selectedClient, setSelectedClient] = useState(data.clients[0]?.id ?? '');
  const [selectedLocation, setSelectedLocation] = useState('');
  const admin = session.user.role === 'workspace_owner' || session.user.role === 'admin';

  async function createClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api('/clients', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ name: form.get('name'), code: form.get('code'), notes: form.get('notes') }) });
      setClientOpen(false); showNotice('Client created.'); await refresh();
    } catch (error) { setError(messageFrom(error)); }
  }

  async function createLocation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api('/locations', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ clientId: form.get('clientId'), name: form.get('name'), address: form.get('address'), notes: form.get('notes') }) });
      setLocationOpen(false); showNotice('Location created.'); await refresh();
    } catch (error) { setError(messageFrom(error)); }
  }

  async function createSystem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api('/systems', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ clientId: form.get('clientId'), locationId: form.get('locationId'), name: form.get('name'), collection: form.get('collection'), manufacturer: form.get('manufacturer'), model: form.get('model'), networkAddress: form.get('networkAddress'), notes: form.get('notes') }) });
      setSystemOpen(false); showNotice('System created.'); await refresh();
    } catch (error) { setError(messageFrom(error)); }
  }

  return (
    <>
      <PageHeader eyebrow="CLIENT → LOCATION → SYSTEM" title="Client environments" copy="Keep every technology record in its real-world context." action={admin && <Button onClick={() => setClientOpen(true)}><Plus /> Add client</Button>} />
      {!data.clients.length ? <section className="panel"><EmptyState icon={Building2} title="Start with a client" copy="Create a client, then add its locations and systems. The local build begins completely empty." action={admin && <Button onClick={() => setClientOpen(true)}><Plus /> Add first client</Button>} /></section> : (
        <section className="client-layout">
          <aside className="panel client-index">
            <span className="eyebrow">CLIENTS</span>
            {data.clients.map((client) => <button key={client.id} className={selectedClient === client.id ? 'selected' : ''} onClick={() => { setSelectedClient(client.id); setSelectedLocation(''); }}><span className="list-icon"><Building2 /></span><span><strong>{client.name}</strong><small>{data.locations.filter((location) => location.client_id === client.id).length} locations</small></span><ChevronRight /></button>)}
          </aside>
          <section className="panel client-detail">
            {(() => {
              const client = data.clients.find((item) => item.id === selectedClient) ?? data.clients[0];
              const locations = data.locations.filter((location) => location.client_id === client.id);
              return <>
                <div className="detail-hero"><span className="detail-icon"><Building2 /></span><div><p className="eyebrow">CLIENT</p><h3>{client.name}</h3><p>{client.notes || 'No client notes yet.'}</p></div><Button variant="outline" onClick={() => { setSelectedClient(client.id); setLocationOpen(true); }}><Plus /> Location</Button></div>
                <div className="hierarchy-list">
                  {locations.length ? locations.map((location) => {
                    const systems = data.systems.filter((system) => system.location_id === location.id);
                    return <article key={location.id} className="hierarchy-card">
                      <button className="hierarchy-heading" onClick={() => setSelectedLocation(selectedLocation === location.id ? '' : location.id)}><span className="list-icon"><MapPin /></span><span><strong>{location.name}</strong><small>{location.address || 'No address'} · {systems.length} systems</small></span><ChevronRight className={selectedLocation === location.id ? 'rotate' : ''} /></button>
                      {selectedLocation === location.id && <div className="systems-list"><div className="inline-heading"><span>Systems & collections</span><Button size="sm" variant="ghost" onClick={() => { setSelectedClient(client.id); setSelectedLocation(location.id); setSystemOpen(true); }}><Plus /> Add system</Button></div>{systems.length ? systems.map((system) => <div key={system.id} className="system-row"><span className="collection-icon"><CollectionIcon collection={system.collection} /></span><span><strong>{system.name}</strong><small>{collectionLabels[system.collection]} · {[system.manufacturer, system.model].filter(Boolean).join(' ') || 'Details not set'}</small></span><Badge variant="outline">{collectionLabels[system.collection]}</Badge></div>) : <p className="inline-empty">No systems recorded at this location.</p>}</div>}
                    </article>;
                  }) : <EmptyState icon={MapPin} title="No locations yet" copy="Add the first location for this client." action={<Button variant="outline" onClick={() => { setSelectedClient(client.id); setLocationOpen(true); }}><Plus /> Add location</Button>} />}
                </div>
              </>;
            })()}
          </section>
        </section>
      )}
      <Dialog open={clientOpen} onOpenChange={setClientOpen}><DialogContent className="form-dialog"><DialogHeader><DialogTitle>Add client</DialogTitle><DialogDescription>Create the top-level client record. No credentials are added automatically.</DialogDescription></DialogHeader><form id="client-form" className="form-grid" onSubmit={createClient}><Field label="Client name"><Input name="name" required /></Field><Field label="Client code"><Input name="code" placeholder="Optional short code" /></Field><Field label="Notes"><Textarea name="notes" /></Field></form><DialogFooter><Button variant="outline" onClick={() => setClientOpen(false)}>Cancel</Button><Button type="submit" form="client-form">Create client</Button></DialogFooter></DialogContent></Dialog>
      <Dialog open={locationOpen} onOpenChange={setLocationOpen}><DialogContent className="form-dialog"><DialogHeader><DialogTitle>Add location</DialogTitle><DialogDescription>Locations keep systems and credentials separated inside a client.</DialogDescription></DialogHeader><form id="location-form" className="form-grid" onSubmit={createLocation}><SelectField name="clientId" label="Client" value={selectedClient} onChange={setSelectedClient} required>{data.clients.map((client) => <option value={client.id} key={client.id}>{client.name}</option>)}</SelectField><Field label="Location name"><Input name="name" required /></Field><Field label="Address"><Input name="address" /></Field><Field label="Notes"><Textarea name="notes" /></Field></form><DialogFooter><Button variant="outline" onClick={() => setLocationOpen(false)}>Cancel</Button><Button type="submit" form="location-form">Create location</Button></DialogFooter></DialogContent></Dialog>
      <Dialog open={systemOpen} onOpenChange={setSystemOpen}><DialogContent className="form-dialog form-dialog-wide"><DialogHeader><DialogTitle>Add system</DialogTitle><DialogDescription>Systems are the context connecting assets and credentials.</DialogDescription></DialogHeader><form id="system-form" className="form-grid two-column" onSubmit={createSystem}><SelectField name="clientId" label="Client" value={selectedClient} onChange={(value) => { setSelectedClient(value); setSelectedLocation(''); }} required>{data.clients.map((client) => <option value={client.id} key={client.id}>{client.name}</option>)}</SelectField><SelectField name="locationId" label="Location" value={selectedLocation} onChange={setSelectedLocation} required><option value="">Select location</option>{data.locations.filter((item) => item.client_id === selectedClient).map((location) => <option value={location.id} key={location.id}>{location.name}</option>)}</SelectField><Field label="System name"><Input name="name" required /></Field><SelectField name="collection" label="Collection" required>{Object.entries(collectionLabels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</SelectField><Field label="Manufacturer"><Input name="manufacturer" /></Field><Field label="Model"><Input name="model" /></Field><Field label="IP address or host"><Input name="networkAddress" /></Field><Field label="Notes"><Textarea name="notes" /></Field></form><DialogFooter><Button variant="outline" onClick={() => setSystemOpen(false)}>Cancel</Button><Button type="submit" form="system-form">Create system</Button></DialogFooter></DialogContent></Dialog>
    </>
  );
}

function CollectionIcon({ collection }: { collection: Collection }) {
  const Icon = collection === 'network' ? Network : collection === 'av_systems' ? MonitorCog : collection === 'voip' ? Phone : collection === 'remote_access' ? Wifi : collection === 'websites_accounts' ? Globe2 : collection === 'access_control' ? ShieldCheck : collection === 'software' ? Clipboard : HardDrive;
  return <Icon />;
}

function VaultPage({ data, session, refresh, secure, showNotice, setError }: PageProps) {
  const [search, setSearch] = useState('');
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<{ credential: Credential; secret: Secret } | null>(null);
  const [revealed, setRevealed] = useState<{ credential: Credential; secret: Secret } | null>(null);
  const [revealSeconds, setRevealSeconds] = useState(30);
  const visible = useMemo(() => data.credentials.filter((credential) => `${credential.name} ${credential.client_name} ${credential.location_name} ${credential.system_name ?? ''} ${collectionLabels[credential.collection]}`.toLowerCase().includes(search.toLowerCase())), [data.credentials, search]);

  useEffect(() => {
    if (!revealed) return;
    setRevealSeconds(30);
    const timer = window.setInterval(() => setRevealSeconds((value) => {
      if (value <= 1) { window.clearInterval(timer); setRevealed(null); return 0; }
      return value - 1;
    }), 1000);
    return () => window.clearInterval(timer);
  }, [revealed]);

  async function reveal(credential: Credential) {
    await secure(async () => {
      const result = await api<{ secret: Secret }>(`/credentials/${credential.id}/secret`, { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ purpose: 'reveal' }) });
      setRevealed({ credential, secret: result.secret });
    });
  }

  async function copyPassword(credential: Credential) {
    await secure(async () => {
      const result = await api<{ secret: Secret }>(`/credentials/${credential.id}/secret`, { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ purpose: 'copy' }) });
      await navigator.clipboard.writeText(result.secret.password || result.secret.apiToken || result.secret.licenseKey || result.secret.pin || result.secret.username);
      showNotice('Secret copied. Clipboard contents are controlled by Windows and your browser.');
    });
  }

  async function editCredential(credential: Credential) {
    await secure(async () => {
      const result = await api<{ secret: Secret }>(`/credentials/${credential.id}/secret`, { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ purpose: 'reveal' }) });
      setEditing({ credential, secret: result.secret });
      setFormOpen(true);
    });
  }

  async function saveCredential(payload: unknown) {
    try {
      await api(editing ? `/credentials/${editing.credential.id}` : '/credentials', { method: editing ? 'PUT' : 'POST', csrfToken: session.csrfToken, body: JSON.stringify(payload) });
      setFormOpen(false); setEditing(null); showNotice(editing ? 'Credential updated.' : 'Credential encrypted and saved.'); await refresh();
    } catch (error) { setError(messageFrom(error)); }
  }

  async function deleteCredential(credential: Credential) {
    if (!window.confirm(`Delete “${credential.name}”? This cannot be undone.`)) return;
    await secure(async () => {
      await api(`/credentials/${credential.id}`, { method: 'DELETE', csrfToken: session.csrfToken });
      showNotice('Credential deleted.'); await refresh();
    });
  }

  return (
    <>
      <PageHeader eyebrow="ENCRYPTED CREDENTIALS" title="Credential vault" copy="Secrets remain encrypted at rest and are returned only after permission and step-up checks." action={<Button onClick={() => { setEditing(null); setFormOpen(true); }} disabled={!data.locations.length}><Plus /> Add credential</Button>} />
      <section className="toolbar"><div className="search-box"><Search /><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search credentials, clients, or systems" /></div><Badge variant="outline">{visible.length} records</Badge></section>
      <section className="panel table-panel">
        {visible.length ? <Table><TableHeader><TableRow><TableHead>Credential</TableHead><TableHead>Context</TableHead><TableHead>Collection</TableHead><TableHead>Verified</TableHead><TableHead className="table-actions">Actions</TableHead></TableRow></TableHeader><TableBody>{visible.map((credential) => <TableRow key={credential.id}><TableCell><div className="primary-cell"><span className="list-icon"><KeyRound /></span><span><strong>{credential.name}</strong><small>{credential.url || 'No URL or address'}</small></span></div></TableCell><TableCell><div className="stacked-cell"><strong>{credential.client_name}</strong><small>{credential.location_name}{credential.system_name ? ` › ${credential.system_name}` : ''}</small></div></TableCell><TableCell><Badge variant="outline">{collectionLabels[credential.collection]}</Badge></TableCell><TableCell>{credential.last_verified_at ? dateTime(credential.last_verified_at) : <span className="muted">Not verified</span>}</TableCell><TableCell><div className="row-actions"><Button size="sm" variant="outline" onClick={() => reveal(credential)}><Eye /> Reveal</Button><Button size="icon-sm" variant="ghost" title="Copy secret" onClick={() => copyPassword(credential)}><Copy /></Button><Button size="icon-sm" variant="ghost" title="Edit" onClick={() => editCredential(credential)}><Pencil /></Button><Button size="icon-sm" variant="destructive" title="Delete" onClick={() => deleteCredential(credential)}><Trash2 /></Button></div></TableCell></TableRow>)}</TableBody></Table> : <EmptyState icon={KeyRound} title={data.credentials.length ? 'No matching credentials' : 'No credentials yet'} copy={data.credentials.length ? 'Try a different search.' : data.locations.length ? 'Add a credential to a real client location. Nothing is preloaded.' : 'Create a client and location before adding credentials.'} action={data.locations.length ? <Button onClick={() => setFormOpen(true)}><Plus /> Add credential</Button> : undefined} />}
      </section>
      <CredentialDialog open={formOpen} setOpen={(open) => { setFormOpen(open); if (!open) setEditing(null); }} data={data} editing={editing} onSave={saveCredential} />
      <Dialog open={Boolean(revealed)} onOpenChange={(open) => { if (!open) setRevealed(null); }}><DialogContent className="secret-dialog"><DialogHeader><DialogTitle>{revealed?.credential.name}</DialogTitle><DialogDescription>{revealed?.credential.client_name} › {revealed?.credential.location_name}</DialogDescription></DialogHeader>{revealed && <div className="secret-fields"><div className="reveal-timer"><Eye /><span>Secrets clear from this screen in {revealSeconds}s</span></div>{Object.entries(revealed.secret).filter(([, value]) => value).map(([key, value]) => <div key={key}><span>{key.replace(/([A-Z])/g, ' $1')}</span><code>{value}</code><Button size="icon-sm" variant="ghost" onClick={() => navigator.clipboard.writeText(value)}><Copy /></Button></div>)}</div>}<DialogFooter><Button variant="outline" onClick={() => setRevealed(null)}><EyeOff /> Hide now</Button></DialogFooter></DialogContent></Dialog>
    </>
  );
}

function CredentialDialog({ open, setOpen, data, editing, onSave }: { open: boolean; setOpen: (open: boolean) => void; data: PageProps['data']; editing: { credential: Credential; secret: Secret } | null; onSave: (payload: unknown) => Promise<void> }) {
  const initialClient = editing?.credential.client_id ?? data.clients[0]?.id ?? '';
  const initialLocation = editing?.credential.location_id ?? data.locations.find((item) => item.client_id === initialClient)?.id ?? '';
  const [clientId, setClientId] = useState(initialClient);
  const [locationId, setLocationId] = useState(initialLocation);
  const [password, setPassword] = useState(editing?.secret.password ?? '');

  useEffect(() => {
    if (!open) return;
    const client = editing?.credential.client_id ?? data.clients[0]?.id ?? '';
    setClientId(client);
    setLocationId(editing?.credential.location_id ?? data.locations.find((item) => item.client_id === client)?.id ?? '');
    setPassword(editing?.secret.password ?? '');
  }, [open, editing, data.clients, data.locations]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await onSave({
      clientId: form.get('clientId'), locationId: form.get('locationId'), systemId: form.get('systemId') || null,
      collection: form.get('collection'), name: form.get('name'), url: form.get('url'),
      lastVerifiedAt: typeof form.get('lastVerifiedAt') === 'string' && form.get('lastVerifiedAt') ? new Date(form.get('lastVerifiedAt') as string).toISOString() : null,
      expiresAt: typeof form.get('expiresAt') === 'string' && form.get('expiresAt') ? new Date(form.get('expiresAt') as string).toISOString() : null,
      secret: { username: form.get('username'), password: form.get('password'), pin: form.get('pin'), apiToken: form.get('apiToken'), licenseKey: form.get('licenseKey'), notes: form.get('secretNotes') },
    });
  }

  const selectedCredential = editing?.credential;
  const selectedSecret = editing?.secret;
  return <Dialog open={open} onOpenChange={setOpen}><DialogContent className="form-dialog form-dialog-wide"><DialogHeader><DialogTitle>{editing ? 'Edit credential' : 'Add credential'}</DialogTitle><DialogDescription>Sensitive fields below are encrypted together before SQLite storage.</DialogDescription></DialogHeader><form id="credential-form" className="form-grid two-column" onSubmit={submit}><SelectField name="clientId" label="Client" value={clientId} onChange={(value) => { setClientId(value); setLocationId(data.locations.find((item) => item.client_id === value)?.id ?? ''); }} required>{data.clients.map((client) => <option value={client.id} key={client.id}>{client.name}</option>)}</SelectField><SelectField name="locationId" label="Location" value={locationId} onChange={setLocationId} required><option value="">Select location</option>{data.locations.filter((location) => location.client_id === clientId).map((location) => <option value={location.id} key={location.id}>{location.name}</option>)}</SelectField><SelectField name="systemId" label="System"><option value="">No linked system</option>{data.systems.filter((system) => system.location_id === locationId).map((system) => <option value={system.id} key={system.id}>{system.name}</option>)}</SelectField><SelectField name="collection" label="Collection" required>{Object.entries(collectionLabels).map(([value, label]) => <option value={value} key={value} selected={selectedCredential?.collection === value}>{label}</option>)}</SelectField><Field label="Credential name"><Input name="name" required defaultValue={selectedCredential?.name} /></Field><Field label="URL, IP, or host"><Input name="url" defaultValue={selectedCredential?.url} /></Field><Field label="Username"><Input name="username" autoComplete="off" defaultValue={selectedSecret?.username} /></Field><Field label="Password"><div className="input-action"><Input name="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /><Button type="button" variant="outline" onClick={() => setPassword(securePassword())}><RefreshCw /> Generate</Button></div></Field><Field label="PIN"><Input name="pin" autoComplete="off" defaultValue={selectedSecret?.pin} /></Field><Field label="API token"><Input name="apiToken" autoComplete="off" defaultValue={selectedSecret?.apiToken} /></Field><Field label="License key"><Input name="licenseKey" autoComplete="off" defaultValue={selectedSecret?.licenseKey} /></Field><Field label="Last verified"><Input name="lastVerifiedAt" type="date" defaultValue={selectedCredential?.last_verified_at?.slice(0, 10)} /></Field><Field label="Expiration date"><Input name="expiresAt" type="date" defaultValue={selectedCredential?.expires_at?.slice(0, 10)} /></Field><Field label="Encrypted notes"><Textarea name="secretNotes" defaultValue={selectedSecret?.notes} /></Field></form><DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="credential-form"><ShieldCheck /> {editing ? 'Save encrypted update' : 'Encrypt and save'}</Button></DialogFooter></DialogContent></Dialog>;
}

function AssetsPage({ data, session, refresh, showNotice, setError }: PageProps) {
  const [type, setType] = useState<'all' | Asset['asset_type']>('all');
  const [open, setOpen] = useState(false);
  const [clientId, setClientId] = useState(data.clients[0]?.id ?? '');
  const [locationId, setLocationId] = useState(data.locations.find((item) => item.client_id === clientId)?.id ?? '');
  const filtered = type === 'all' ? data.assets : data.assets.filter((asset) => asset.asset_type === type);

  async function createAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api('/assets', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ clientId: form.get('clientId'), locationId: form.get('locationId'), systemId: form.get('systemId') || null, assetType: form.get('assetType'), name: form.get('name'), vendor: form.get('vendor'), versionOrModel: form.get('versionOrModel'), identifier: form.get('identifier'), url: form.get('url'), notes: form.get('notes') }) });
      setOpen(false); showNotice('Asset record created.'); await refresh();
    } catch (error) { setError(messageFrom(error)); }
  }

  return <>
    <PageHeader eyebrow="TECHNOLOGY RECORDS" title="Devices, software & accounts" copy="Inventory records link back to the same clients, locations, and systems as the vault." action={<Button onClick={() => setOpen(true)} disabled={!data.locations.length}><Plus /> Add record</Button>} />
    <section className="toolbar tab-toolbar"><div>{(['all', 'device', 'software', 'website_account'] as const).map((item) => <button key={item} className={type === item ? 'active' : ''} onClick={() => setType(item)}>{item === 'all' ? 'All records' : item === 'website_account' ? 'Websites & accounts' : `${item[0].toUpperCase()}${item.slice(1)}`}</button>)}</div><Badge variant="outline">{filtered.length} records</Badge></section>
    <section className="panel table-panel">{filtered.length ? <Table><TableHeader><TableRow><TableHead>Record</TableHead><TableHead>Type</TableHead><TableHead>Client & location</TableHead><TableHead>Vendor / version</TableHead><TableHead>Identifier</TableHead></TableRow></TableHeader><TableBody>{filtered.map((asset) => <TableRow key={asset.id}><TableCell><div className="primary-cell"><span className="list-icon">{asset.asset_type === 'device' ? <HardDrive /> : asset.asset_type === 'software' ? <MonitorCog /> : <Globe2 />}</span><span><strong>{asset.name}</strong><small>{asset.system_name || 'No linked system'}</small></span></div></TableCell><TableCell><Badge variant="outline">{asset.asset_type.replace('_', ' ')}</Badge></TableCell><TableCell><div className="stacked-cell"><strong>{asset.client_name}</strong><small>{asset.location_name}</small></div></TableCell><TableCell>{[asset.vendor, asset.version_or_model].filter(Boolean).join(' · ') || <span className="muted">Not set</span>}</TableCell><TableCell>{asset.identifier || <span className="muted">Not set</span>}</TableCell></TableRow>)}</TableBody></Table> : <EmptyState icon={HardDrive} title="No asset records yet" copy="Add devices, software, or website/account references. Passwords belong in the encrypted credential vault." action={data.locations.length ? <Button onClick={() => setOpen(true)}><Plus /> Add record</Button> : undefined} />}</section>
    <Dialog open={open} onOpenChange={setOpen}><DialogContent className="form-dialog form-dialog-wide"><DialogHeader><DialogTitle>Add technology record</DialogTitle><DialogDescription>Inventory fields are non-secret. Store passwords, tokens, PINs, and private notes in a credential record.</DialogDescription></DialogHeader><form id="asset-form" className="form-grid two-column" onSubmit={createAsset}><SelectField name="clientId" label="Client" value={clientId} onChange={(value) => { setClientId(value); setLocationId(data.locations.find((item) => item.client_id === value)?.id ?? ''); }} required>{data.clients.map((client) => <option key={client.id} value={client.id}>{client.name}</option>)}</SelectField><SelectField name="locationId" label="Location" value={locationId} onChange={setLocationId} required><option value="">Select location</option>{data.locations.filter((location) => location.client_id === clientId).map((location) => <option key={location.id} value={location.id}>{location.name}</option>)}</SelectField><SelectField name="systemId" label="Linked system"><option value="">No linked system</option>{data.systems.filter((system) => system.location_id === locationId).map((system) => <option key={system.id} value={system.id}>{system.name}</option>)}</SelectField><SelectField name="assetType" label="Record type" required><option value="device">Device</option><option value="software">Software</option><option value="website_account">Website/account reference</option></SelectField><Field label="Name"><Input name="name" required /></Field><Field label="Vendor"><Input name="vendor" /></Field><Field label="Model or version"><Input name="versionOrModel" /></Field><Field label="Serial, license reference, or account ID"><Input name="identifier" /></Field><Field label="URL"><Input name="url" /></Field><Field label="Notes"><Textarea name="notes" /></Field></form><DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="asset-form">Create record</Button></DialogFooter></DialogContent></Dialog>
  </>;
}

function UsersPage({ data, session, refresh, secure, showNotice, setError, setSession }: PageProps) {
  const [userOpen, setUserOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [permissionOpen, setPermissionOpen] = useState(false);
  const [targetUserId, setTargetUserId] = useState(data.users.find((user) => user.role !== 'workspace_owner')?.id ?? '');
  const [clientId, setClientId] = useState(data.clients[0]?.id ?? '');
  const [locationId, setLocationId] = useState('');

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api('/users', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ name: form.get('name'), email: form.get('email'), password: form.get('password'), role: form.get('role') }) });
      setUserOpen(false); showNotice('User created. MFA enrollment is forced at first sign-in.'); await refresh();
    } catch (error) { setError(messageFrom(error)); }
  }

  async function savePermission(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await secure(async () => {
      await api('/permissions', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ userId: form.get('userId'), clientId: form.get('clientId') || null, locationId: form.get('locationId') || null, collection: form.get('collection') || null, canView: form.get('canView') === 'on', canManage: form.get('canManage') === 'on', canReveal: form.get('canReveal') === 'on', canExport: form.get('canExport') === 'on' }) });
      setPermissionOpen(false); showNotice('Scoped permission saved and audited.'); await refresh();
    });
  }

  async function resetMfa(user: User) {
    if (!window.confirm(`Reset MFA for ${user.name}? Their sessions and passkeys will be revoked.`)) return;
    await secure(async () => {
      await api(`/users/${user.id}/reset-mfa`, { method: 'POST', csrfToken: session.csrfToken });
      showNotice('MFA enrollment reset. The user must enroll again at next sign-in.'); await refresh();
    });
  }

  async function updateUserName(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editingUser) return;
    const form = new FormData(event.currentTarget);
    const nameValue = form.get('name');
    const name = typeof nameValue === 'string' ? nameValue.trim() : '';
    await secure(async () => {
      const updated = await api<User>(`/users/${editingUser.id}`, {
        method: 'PATCH',
        csrfToken: session.csrfToken,
        body: JSON.stringify({ name }),
      });
      if (updated.id === session.user.id) setSession({ ...session, user: updated });
      setEditingUser(null);
      showNotice('User name updated and audited.');
      await refresh();
    });
  }

  return <>
    <PageHeader eyebrow="ROLE-BASED ACCESS" title="Users & permissions" copy="Roles set the ceiling; client, location, and collection grants determine the records a user can access." action={<div className="heading-actions"><Button variant="outline" onClick={() => setPermissionOpen(true)} disabled={!data.clients.length || data.users.length < 2}><UserCog /> Grant access</Button><Button onClick={() => setUserOpen(true)}><Plus /> Add user</Button></div>} />
    <section className="panel table-panel">{data.users.length ? <Table><TableHeader><TableRow><TableHead>User</TableHead><TableHead>Role</TableHead><TableHead>MFA</TableHead><TableHead>Recovery</TableHead><TableHead>Last sign-in</TableHead><TableHead className="table-actions">Actions</TableHead></TableRow></TableHeader><TableBody>{data.users.map((user) => <TableRow key={user.id}><TableCell><div className="primary-cell"><span className="user-avatar">{initials(user.name)}</span><span><strong>{user.name}</strong><small>{user.email}</small></span></div></TableCell><TableCell><Badge variant={user.role === 'workspace_owner' || user.role === 'admin' ? 'default' : 'outline'}>{roleLabels[user.role]}</Badge></TableCell><TableCell><span className={user.mfaEnabled ? 'good-status' : 'warn-status'}>{user.mfaEnabled ? <Check /> : <AlertTriangle />}{user.mfaEnabled ? `${user.passkeyCount ? 'TOTP + passkey' : 'TOTP'}` : 'Enrollment required'}</span></TableCell><TableCell>{user.recoveryCodesRemaining} unused</TableCell><TableCell>{dateTime(user.lastLoginAt)}</TableCell><TableCell><div className="row-actions"><Button size="sm" variant="outline" onClick={() => setEditingUser(user)}><Pencil /> Edit name</Button><Button size="sm" variant="outline" onClick={() => resetMfa(user)} disabled={user.id === session.user.id}><RefreshCw /> Reset MFA</Button></div></TableCell></TableRow>)}</TableBody></Table> : <EmptyState icon={Users} title="No users found" copy="The workspace owner should always appear here." />}</section>
    <section className="role-grid">{Object.entries(roleLabels).map(([role, label]) => <article className="role-card" key={role}><span><Users /></span><strong>{label}</strong><p>{role === 'workspace_owner' ? 'Full control and key stewardship.' : role === 'admin' ? 'Workspace administration and all client records.' : role === 'technician' ? 'Access only to explicitly assigned client scopes.' : role === 'client_admin' ? 'Manage granted client or location scopes.' : role === 'client_user' ? 'Use granted records without administrative control.' : 'Metadata viewing only unless reveal is explicitly granted.'}</p></article>)}</section>
    <Dialog open={userOpen} onOpenChange={setUserOpen}><DialogContent className="form-dialog"><DialogHeader><DialogTitle>Add user</DialogTitle><DialogDescription>Give the user this initial password through a separate secure channel. They must enroll an authenticator on first sign-in.</DialogDescription></DialogHeader><form id="user-form" className="form-grid" onSubmit={createUser}><Field label="Full name"><Input name="name" required /></Field><Field label="Email"><Input name="email" type="email" required /></Field><SelectField name="role" label="Role" required>{Object.entries(roleLabels).filter(([role]) => role !== 'workspace_owner').map(([role, label]) => <option value={role} key={role}>{label}</option>)}</SelectField><Field label="Initial password" hint="At least 14 characters with uppercase, lowercase, number, and symbol."><Input name="password" type="password" minLength={14} required autoComplete="new-password" /></Field></form><DialogFooter><Button variant="outline" onClick={() => setUserOpen(false)}>Cancel</Button><Button type="submit" form="user-form">Create user</Button></DialogFooter></DialogContent></Dialog>
    <Dialog open={Boolean(editingUser)} onOpenChange={(open) => { if (!open) setEditingUser(null); }}><DialogContent className="form-dialog"><DialogHeader><DialogTitle>Edit user name</DialogTitle><DialogDescription>Update the display name for {editingUser?.email}. The account email and permissions are unchanged.</DialogDescription></DialogHeader><form id="edit-user-form" className="form-grid" onSubmit={updateUserName}><Field label="Full name"><Input name="name" required minLength={2} maxLength={120} defaultValue={editingUser?.name} autoFocus /></Field></form><DialogFooter><Button variant="outline" onClick={() => setEditingUser(null)}>Cancel</Button><Button type="submit" form="edit-user-form"><Pencil /> Verify & save name</Button></DialogFooter></DialogContent></Dialog>
    <Dialog open={permissionOpen} onOpenChange={setPermissionOpen}><DialogContent className="form-dialog form-dialog-wide"><DialogHeader><DialogTitle>Grant scoped access</DialogTitle><DialogDescription>More specific location or collection grants override broader client grants.</DialogDescription></DialogHeader><form id="permission-form" className="form-grid two-column" onSubmit={savePermission}><SelectField name="userId" label="User" value={targetUserId} onChange={setTargetUserId} required><option value="">Select user</option>{data.users.filter((user) => user.role !== 'workspace_owner' && user.role !== 'admin').map((user) => <option key={user.id} value={user.id}>{user.name} — {roleLabels[user.role]}</option>)}</SelectField><SelectField name="clientId" label="Client" value={clientId} onChange={(value) => { setClientId(value); setLocationId(''); }} required><option value="">Select client</option>{data.clients.map((client) => <option key={client.id} value={client.id}>{client.name}</option>)}</SelectField><SelectField name="locationId" label="Location (optional)" value={locationId} onChange={setLocationId}><option value="">All client locations</option>{data.locations.filter((location) => location.client_id === clientId).map((location) => <option key={location.id} value={location.id}>{location.name}</option>)}</SelectField><SelectField name="collection" label="Collection (optional)"><option value="">All collections</option>{Object.entries(collectionLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</SelectField><fieldset className="permission-checks"><legend>Allowed actions</legend>{[['canView', 'View records'], ['canManage', 'Create and edit'], ['canReveal', 'Reveal and copy secrets'], ['canExport', 'Export documentation']].map(([name, label]) => <label key={name}><input name={name} type="checkbox" defaultChecked={name === 'canView'} /><span>{label}</span></label>)}</fieldset></form><DialogFooter><Button variant="outline" onClick={() => setPermissionOpen(false)}>Cancel</Button><Button type="submit" form="permission-form"><ShieldCheck /> Verify & save grant</Button></DialogFooter></DialogContent></Dialog>
  </>;
}

function AuditPage({ data }: PageProps) {
  const eventLabel = (value: string) => value.split('.').map((part) => `${part[0]?.toUpperCase()}${part.slice(1)}`).join(' · ');
  return <><PageHeader eyebrow="TAMPER-EVIDENT EVENT CHAIN" title="Security audit" copy="Sign-in, MFA, secret access, changes, permissions, shares, backups, and exports are recorded without secret values." /><section className="panel audit-list">{data.audit.length ? data.audit.map((entry) => <article key={entry.id}><span className={`audit-icon ${entry.outcome}`}><Activity /></span><div><div><strong>{eventLabel(entry.event_type)}</strong><Badge variant={entry.outcome === 'success' ? 'outline' : 'destructive'}>{entry.outcome}</Badge></div><p>{entry.actor_name || 'Unknown / unauthenticated'} · {dateTime(entry.occurred_at)}</p><small>{entry.target_type ? `Target: ${entry.target_type}` : 'Workspace event'}</small></div></article>) : <EmptyState icon={Activity} title="No audit events yet" copy="Security activity will appear here." />}</section></>;
}

function SettingsPage({ session, setSession, secure, showNotice, setError, signOut }: PageProps) {
  const [passkeys, setPasskeys] = useState<Array<{ id: string; name: string; deviceType: string; backedUp: boolean }>>([]);
  const [shares, setShares] = useState<{ enabled: boolean; message: string } | null>(null);
  const admin = session.user.role === 'workspace_owner' || session.user.role === 'admin';

  useEffect(() => {
    const passkeyRequest = session.capabilities?.passkeys === false ? Promise.resolve([]) : api<typeof passkeys>('/passkeys');
    void Promise.all([passkeyRequest, api<{ enabled: boolean; message: string }>('/shares/status')]).then(([keys, status]) => { setPasskeys(keys); setShares(status); }).catch((error) => setError(messageFrom(error)));
  }, [session.capabilities?.passkeys, setError]);

  async function registerPasskey() {
    await secure(async () => {
      const result = await api<{ challengeId: string; options: Parameters<typeof startRegistration>[0]['optionsJSON'] }>('/passkeys/register/options', { method: 'POST', csrfToken: session.csrfToken });
      const credential = await startRegistration({ optionsJSON: result.options });
      await api('/passkeys/register/verify', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ challengeId: result.challengeId, response: credential, name: 'Windows Hello / security key' }) });
      const next = await api<typeof passkeys>('/passkeys'); setPasskeys(next); showNotice('Passkey enrolled.');
      setSession({ ...session, user: { ...session.user, passkeyCount: next.length } });
    });
  }

  async function exportDocumentation() {
    await secure(async () => { await downloadFromApi('/exports/documentation', { clientId: null }, session.csrfToken); showNotice('Documentation exported without passwords.'); });
  }
  async function backup() {
    await secure(async () => { await downloadFromApi('/exports/backup', {}, session.csrfToken); showNotice('Encrypted vault backup downloaded.'); });
  }

  return <>
    <PageHeader eyebrow="SECURITY & RECOVERY" title="Workspace security" copy="Review MFA, passkeys, safe exports, and backup controls." />
    <section className="settings-grid">
      <article className="panel setting-card"><div className="setting-title"><span className="stat-icon"><Smartphone /></span><div><h3>Authenticator MFA</h3><p>Required for this account</p></div><Badge>{session.user.mfaEnabled ? 'Enabled' : 'Required'}</Badge></div><dl><div><dt>Recovery codes</dt><dd>{session.user.recoveryCodesRemaining} unused</dd></div><div><dt>Step-up window</dt><dd>5 minutes</dd></div></dl><Alert><ShieldCheck /><AlertDescription>Admins can reset enrollment, but cannot view another user’s MFA secret or recovery codes.</AlertDescription></Alert></article>
      <article className="panel setting-card"><div className="setting-title"><span className="stat-icon"><KeyRound /></span><div><h3>Passkeys / Windows Hello</h3><p>Optional second factor</p></div><Badge variant="outline">{session.capabilities?.passkeys === false ? 'Local app only' : `${passkeys.length} enrolled`}</Badge></div>{passkeys.map((key) => <div className="passkey-row" key={key.id}><KeyRound /><span><strong>{key.name}</strong><small>{key.deviceType || 'Passkey'}{key.backedUp ? ' · synced' : ''}</small></span><Check /></div>)}{session.capabilities?.passkeys === false ? <Alert><ShieldCheck /><AlertDescription>Passkeys remain available in the Windows app while hosted WebAuthn enrollment completes validation.</AlertDescription></Alert> : <Button variant="outline" onClick={registerPasskey}><Plus /> Add passkey</Button>}<p className="setting-note">Your password is always required to unlock the vault key.</p></article>
      <article className="panel setting-card"><div className="setting-title"><span className="stat-icon"><FileJson /></span><div><h3>Documentation export</h3><p>Client technology records</p></div><Badge variant="outline">Secrets omitted</Badge></div><p className="setting-copy">Creates a JSON documentation package with clients, locations, systems, and assets. Passwords, PINs, tokens, license keys, and encrypted notes are always omitted.</p><Button variant="outline" onClick={exportDocumentation}><Download /> Export safe documentation</Button></article>
      <article className="panel setting-card"><div className="setting-title"><span className="stat-icon"><HardDrive /></span><div><h3>Encrypted vault backup</h3><p>Workspace owner and admin</p></div><Badge variant="outline">{session.capabilities?.sqliteBackup === false ? 'Encrypted JSON' : 'SQLite'}</Badge></div><p className="setting-copy">Downloads a consistent encrypted snapshot. Credential blobs and MFA seeds remain encrypted; the backup still contains sensitive metadata and password hashes.</p><Button variant="outline" disabled={!admin} onClick={backup}><Download /> Download encrypted backup</Button></article>
      <article className="panel setting-card disabled-card"><div className="setting-title"><span className="stat-icon"><Wifi /></span><div><h3>Temporary sharing</h3><p>Intentionally unavailable</p></div><Badge variant="destructive">Local-only</Badge></div><p className="setting-copy">{shares?.message ?? 'Temporary sharing is disabled because localhost links cannot be shared safely.'}</p><Button variant="outline" disabled><ShieldX /> Sharing disabled</Button></article>
      <article className="panel setting-card"><div className="setting-title"><span className="stat-icon"><LogOut /></span><div><h3>Session</h3><p>Unlocked key exists only in memory</p></div></div><dl><div><dt>Session expires</dt><dd>{dateTime(session.expiresAt)}</dd></div><div><dt>Account</dt><dd>{session.user.email}</dd></div></dl><Button variant="destructive" onClick={signOut}><LogOut /> Lock and sign out</Button></article>
    </section>
  </>;
}

function StepUpDialog({ open, setOpen, session, onVerified }: { open: boolean; setOpen: (open: boolean) => void; session: Session; onVerified: (until: string) => Promise<void> }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function verifyCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{ stepUpUntil: string }>('/auth/step-up', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ code: form.get('code') }) });
      await onVerified(result.stepUpUntil);
    } catch (nextError) { setError(messageFrom(nextError)); } finally { setBusy(false); }
  }

  async function verifyPasskey() {
    setBusy(true); setError('');
    try {
      const result = await api<{ challengeId: string; options: Parameters<typeof startAuthentication>[0]['optionsJSON'] }>('/auth/passkey/step-up/options', { method: 'POST', csrfToken: session.csrfToken });
      const credential = await startAuthentication({ optionsJSON: result.options });
      const verified = await api<{ stepUpUntil: string }>('/auth/passkey/step-up/verify', { method: 'POST', csrfToken: session.csrfToken, body: JSON.stringify({ challengeId: result.challengeId, response: credential }) });
      await onVerified(verified.stepUpUntil);
    } catch (nextError) { setError(messageFrom(nextError)); } finally { setBusy(false); }
  }

  return <Dialog open={open} onOpenChange={setOpen}><DialogContent className="stepup-dialog"><DialogHeader><span className="auth-icon"><ShieldCheck /></span><DialogTitle>Confirm your identity</DialogTitle><DialogDescription>This sensitive action needs a fresh MFA check. Approval lasts five minutes.</DialogDescription></DialogHeader><form id="stepup-form" className="auth-form" onSubmit={verifyCode}><Field label="Authenticator or recovery code"><Input name="code" inputMode="numeric" autoComplete="one-time-code" required /></Field>{error && <Alert variant="destructive"><AlertTriangle /><AlertDescription>{error}</AlertDescription></Alert>}</form><DialogFooter><Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>{session.user.passkeyCount > 0 && <Button variant="outline" onClick={verifyPasskey} disabled={busy}><KeyRound /> Use passkey</Button>}<Button type="submit" form="stepup-form" disabled={busy}>{busy ? <RefreshCw className="spin" /> : <ShieldCheck />} Verify</Button></DialogFooter></DialogContent></Dialog>;
}
