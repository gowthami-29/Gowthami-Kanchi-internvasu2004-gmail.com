import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';

const API = '';
let accessToken = null;
const themeMap = {
  cobalt: {
    background: '#eef4ff',
    sidebar: '#102a56',
    accent: '#2563eb',
    soft: '#dbeafe',
  },
  default: {
    background: '#f5f7fb',
    sidebar: '#18212f',
    accent: '#4f46e5',
    soft: '#e0e7ff',
  },
};

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    credentials: 'include',
    headers: {
  'Content-Type': 'application/json',
  ...(accessToken
    ? { Authorization: `Bearer ${accessToken}` }
    : {}),
  ...(options.headers || {}),
},
    ...options,
  });

  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
  const rawMessage =
    body?.message ??
    body?.error ??
    body?.reason ??
    `Request failed: ${response.status}`;

  const message =
    typeof rawMessage === 'string'
      ? rawMessage
      : typeof rawMessage?.message === 'string'
        ? rawMessage.message
        : typeof rawMessage?.error === 'string'
          ? rawMessage.error
          : 'Invalid email or password. Please check your credentials.';

  const error = new Error(message);

  error.status = response.status;
  error.body = body;
  throw error;
}

  return body;
}

function App() {
  const path = window.location.pathname;

  if (path.startsWith('/invite/')) {
    return <InvitePage token={decodeURIComponent(path.slice('/invite/'.length))} />;
  }

  return <Console />;
}

/* -------------------------------------------------------------------------- */
/* Login                                                                      */
/* -------------------------------------------------------------------------- */

function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError('');

    if (!email.trim() || !password) {
      setError('Please enter your email and password.');
      return;
    }

    setLoading(true);

    try {
      const result = await api('/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: email.trim(),
          password,
        }),
      });

      accessToken = result?.token || null;
onLogin(result);
    } catch (err) {
      setError(
        err.message ||
          'Invalid email or password. Please check your credentials.'
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={styles.loginPage}>
      <form data-testid="login-form" onSubmit={submit} style={styles.loginCard}>
        <div style={styles.brandMark}>R</div>
        <div style={styles.eyebrow}>REMOTE OPERATIONS</div>
        <h1 style={styles.loginTitle}>Welcome back</h1>
        <p style={styles.muted}>
          Sign in to manage your devices and remote sessions.
        </p>

        <label style={styles.label}>Email</label>
        <input
          data-testid="login-email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          type="email"
          autoComplete="email"
          placeholder="you@example.com"
          style={styles.input}
        />

        <label style={styles.label}>Password</label>
        <input
          data-testid="login-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          type="password"
          autoComplete="current-password"
          placeholder="••••••••"
          style={styles.input}
        />

        {error && (
          <div data-testid="login-error" style={styles.error}>
            {error}
          </div>
        )}

        <button
          data-testid="login-submit"
          type="submit"
          style={styles.primaryButton}
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}

/* -------------------------------------------------------------------------- */
/* Main console                                                               */
/* -------------------------------------------------------------------------- */

function Console() {
  const [session, setSession] = useState(null);
  const [booting, setBooting] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    restoreSession();
  }, []);

  async function restoreSession() {
    try {
      const result = await api('/v1/auth/refresh', {
        method: 'POST',
      });

      if (result?.token || result?.user || result?.orgId) {
  accessToken = result?.token || null;
  setSession(result);
}
    } catch {
      // No existing refresh session.
    } finally {
      setBooting(false);
    }
  }

  if (booting) {
    return (
      <main style={styles.centerPage}>
        <div style={styles.loadingCard}>Loading RemoteOps…</div>
      </main>
    );
  }

  if (!session) {
    return (
      <Login
        onLogin={(result) => {
          setSession(result);
          setError('');
        }}
      />
    );
  }

  return (
    <ConsoleShell
      session={session}
      onSessionChange={setSession}
      error={error}
      setError={setError}
    />
  );
}

/* -------------------------------------------------------------------------- */
/* Shell                                                                      */
/* -------------------------------------------------------------------------- */

function ConsoleShell({ session, onSessionChange, error, setError }) {
  const [activePage, setActivePage] = useState('devices');
  const [orgs, setOrgs] = useState([]);
  const [orgLoading, setOrgLoading] = useState(false);

  const currentOrg =
    orgs.find((org) => org.id === session.orgId) ||
    orgs.find((org) => org.id === session.user?.orgId);

  const themeName = currentOrg?.theme || 'cobalt';
  const theme = themeMap[themeName] || themeMap.default;

  useEffect(() => {
    loadOrganizations();
  }, [session.orgId]);

  async function loadOrganizations() {
    if (Array.isArray(session.orgs) && session.orgs.length) {
      setOrgs(session.orgs);
      return;
    }

    // The login response normally provides orgs. If it does not,
    // keep the active organization available.
    if (session.orgId) {
      setOrgs([
        {
          id: session.orgId,
          name: session.orgName || 'Organization',
          theme: session.orgTheme || 'cobalt',
        },
      ]);
    }
  }

  async function switchOrg(orgId) {
    if (orgId === session.orgId) return;

    setOrgLoading(true);
    setError('');

    try {
      const result = await api('/v1/auth/token', {
        method: 'POST',
        body: JSON.stringify({ orgId }),
      });
      accessToken = result?.token || accessToken;
      const nextOrg =
        orgs.find((org) => org.id === orgId) || {
          id: orgId,
          name: 'Organization',
          theme: 'cobalt',
        };

      onSessionChange({
        ...session,
        ...result,
        orgId: result.orgId,
        role: result.role,
        orgs,
        orgName: nextOrg.name,
        orgTheme: nextOrg.theme,
      });

      setActivePage('devices');
    } catch (err) {
      setError(err.message);
    } finally {
      setOrgLoading(false);
    }
  }

  async function createOrganization() {
    const name = window.prompt('Organization name');

    if (!name?.trim()) return;

    try {
      const result = await api('/v1/orgs', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim() }),
      });

      const newOrg = {
        id: result.id,
        name: result.name,
        theme: 'default',
      };

      const nextOrgs = [...orgs, newOrg];
      setOrgs(nextOrgs);

      const token = await api('/v1/auth/token', {
        method: 'POST',
        body: JSON.stringify({ orgId: result.id }),
      });
      accessToken = token?.token || accessToken;

      onSessionChange({
        ...session,
        ...token,
        orgId: result.id,
        role: 'owner',
        orgs: nextOrgs,
        orgName: result.name,
        orgTheme: 'default',
      });

      setActivePage('devices');
    } catch (err) {
      setError(err.message);
    }
  }

  const nav = [
  { id: 'devices', label: 'Devices', icon: '▣', permission: 'device:view' },
  { id: 'people', label: 'People', icon: '♙', permission: 'user:read' },
  { id: 'grants', label: 'Grants', icon: '◇', permission: null },
  { id: 'sessions', label: 'Sessions', icon: '◉', permission: 'session:view' },
  { id: 'audit', label: 'Audit', icon: '≡', permission: 'audit:read' },
  { id: 'admin', label: 'Admin', icon: '⚙', permission: 'org:update' },
];

  return (
    <div
      data-testid="app-shell"
      data-org-id={session.orgId}
      data-org-theme={themeName}
      style={{
        ...styles.shell,
        background: theme.background,
      }}
    >
      <aside
        style={{
          ...styles.sidebar,
          background: theme.sidebar,
        }}
      >
        <div style={styles.sidebarBrand}>
          <div style={styles.sidebarLogo}>R</div>
          <div>
            <div style={styles.sidebarTitle}>RemoteOps</div>
            <div style={styles.sidebarSubtitle}>Control Console</div>
          </div>
        </div>

        <div style={styles.orgSection}>
          <div style={styles.sidebarLabel}>ORGANIZATION</div>

          {orgs.map((org) => (
            <button
              key={org.id}
              data-testid="org-option"
              data-org-id={org.id}
              onClick={() => switchOrg(org.id)}
              style={{
                ...styles.orgButton,
                background:
                  org.id === session.orgId
                    ? 'rgba(255,255,255,.14)'
                    : 'transparent',
              }}
            >
              <span style={styles.orgDot} />
              <span>{org.name}</span>
              {org.id === session.orgId && <span>✓</span>}
            </button>
          ))}

          <button
            data-testid="create-org"
            onClick={createOrganization}
            style={styles.createOrgButton}
          >
            + New organization
          </button>
        </div>

        <nav style={styles.nav}>
          {nav.map((item) => {
         const visible =
  item.id === 'devices'
    ? true
    : item.id === 'sessions'
      ? true
      : item.id === 'grants'
        ? session.role !== 'operator'
        : item.id === 'admin'
          ? session.role === 'owner' || session.role === 'admin'
          : hasPermission(session, item.permission);

if (!visible) return null;

            return (
              <button
                key={item.id}
                data-testid={`nav-${item.id}`}
                onClick={() => setActivePage(item.id)}
                style={{
                  ...styles.navButton,
                  ...(activePage === item.id
                    ? styles.navButtonActive
                    : {}),
                }}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div style={styles.sidebarFooter}>
          <div style={styles.userAvatar}>
            {(session.user?.name || session.user?.email || 'U')
              .slice(0, 1)
              .toUpperCase()}
          </div>

          <div style={{ minWidth: 0 }}>
            <div style={styles.footerName}>
              {session.user?.name || 'User'}
            </div>
            <div style={styles.footerRole} data-testid="active-role">
              {session.role}
            </div>
          </div>
        </div>
      </aside>

      <main style={styles.main}>
        <header style={styles.header}>
          <div>
            <div style={styles.breadcrumb}>REMOTEOPS / CONSOLE</div>
            <h1 style={styles.pageTitle}>
              {nav.find((item) => item.id === activePage)?.label || 'Devices'}
            </h1>
          </div>

          <div style={styles.headerRight}>
            {orgLoading && <span style={styles.muted}>Switching…</span>}
            <span style={styles.rolePill}>{session.role}</span>
          </div>
        </header>

        {error && (
          <div style={styles.globalError} onClick={() => setError('')}>
            {error}
          </div>
        )}

        <section style={styles.content}>
          {activePage === 'devices' && (
            <Devices
  orgId={session.orgId}
  sessionPermissions={sessionPermissions(session)}
/>
          )}

          {activePage === 'people' && (
            <People orgId={session.orgId} />
          )}

          {activePage === 'grants' && (
            <Grants
              orgId={session.orgId}
              session={session}
            />
          )}

          {activePage === 'sessions' && (
            <Sessions orgId={session.orgId} />
          )}

          {activePage === 'audit' && (
            <Audit orgId={session.orgId} />
          )}

          {activePage === 'admin' && (
            <Admin
              orgId={session.orgId}
              role={session.role}
              onOrganizationCreated={createOrganization}
            />
          )}
        </section>
      </main>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Permission helper                                                          */
/* -------------------------------------------------------------------------- */
function sessionPermissions(session) {
  const permissions = session?.permissions || {};

  return Object.fromEntries(
    Object.entries(permissions).map(([key, value]) => [
      key,
      typeof value === 'string'
        ? value
        : value?.effect || 'deny',
    ])
  );
}

function hasPermission(session, permission) {
  return sessionPermissions(session)[permission] === 'allow';
}

/* -------------------------------------------------------------------------- */
/* Devices                                                                    */
/* -------------------------------------------------------------------------- */

function Devices({ orgId, sessionPermissions }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    setError('');

    try {
      const result = await api(`/v1/orgs/${orgId}/devices`);
      setDevices(result.devices || []);
    } catch (err) {
      setError(err.message);
      setDevices([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, [orgId]);

  if (loading) {
    return <LoadingState text="Loading devices…" />;
  }

  if (error) {
    return <ErrorState message={error} />;
  }

  return (
    <div>
      <PageIntro
        title="Devices"
        description="Devices visible to you in this organization."
      />

      {devices.length === 0 ? (
        <div data-testid="devices-empty" style={styles.empty}>
          <div style={styles.emptyIcon}>▣</div>
          <h3>No devices yet</h3>
          <p>No devices are currently available in this organization.</p>
        </div>
      ) : (
        <div style={styles.card}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Device</th>
                <th style={styles.th}>Type</th>
                <th style={styles.th}>Status</th>
                <th style={styles.th}>Actions</th>
              </tr>
            </thead>

            <tbody>
              {devices.map((device) => (
                <tr
                  key={device.id}
                  data-testid="device-row"
                  data-device-id={device.id}
                  style={styles.tr}
                >
                  <td style={styles.td}>
                    <div style={styles.deviceName}>{device.name}</div>
                    <div style={styles.deviceId}>{device.id}</div>
                  </td>

                  <td style={styles.td}>
                    <span style={styles.typePill}>
                      {device.kind || 'device'}
                    </span>
                  </td>

                  <td style={styles.td}>
                    <span
                      style={{
                        ...styles.status,
                        ...(device.online
                          ? styles.statusOnline
                          : styles.statusOffline),
                      }}
                    >
                      <span style={styles.statusDot} />
                      {device.online ? 'Online' : 'Offline'}
                    </span>
                  </td>

                  <td style={styles.td}>
                    <div style={styles.actionRow}>
                      {permissionButton(
  orgId,
  device,
  'device:control',
  'Control',
  sessionPermissions
)}

{permissionButton(
  orgId,
  device,
  'device:terminal',
  'Terminal',
  sessionPermissions
)}

{permissionButton(
  orgId,
  device,
  'device:view',
  'View',
  sessionPermissions
)}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function permissionButton(orgId, device, permission, label, sessionPermissions) {
  const value = device.permissions?.[permission];
  

  const effect =
    typeof value === 'string'
      ? value
      : value?.effect || 'deny';

  if (effect !== 'allow') {
    return null;
  }

  return (
    <button
      data-permission={permission}
      data-state="unlocked"
      onClick={() => startSession(orgId,device.id, permission)}
      style={styles.smallButton}
    >
      {label}
    </button>
  );
}

async function startSession(orgId, deviceId, permission) {
  const mode =
    permission === 'device:terminal'
      ? 'terminal'
      : permission === 'device:control'
        ? 'control'
        : 'view';

  try {
    await api(`/v1/orgs/${orgId}/sessions`, {
      method: 'POST',
      body: JSON.stringify({
        deviceId,
        mode,
      }),
    });
    } catch (err) {
    window.alert(err.message || 'Failed to start session');
  }
}

/* -------------------------------------------------------------------------- */
/* People                                                                     */
/* -------------------------------------------------------------------------- */

function People({ orgId }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    load();
  }, [orgId]);

  async function load() {
    setLoading(true);

    try {
      const result = await api(`/v1/orgs/${orgId}/members`);
      setUsers(
        result.members ||
          result.users ||
          result.data ||
          []
      );
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <LoadingState text="Loading people…" />;

  if (error) {
    return <ErrorState message={error} />;
  }

  return (
    <div>
      <PageIntro
        title="People"
        description="Members of this organization."
      />

      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Person</th>
              <th style={styles.th}>Role</th>
              <th style={styles.th}>Status</th>
            </tr>
          </thead>

          <tbody>
            {users.map((user) => (
              <tr
                key={user.user_id || user.id}
                data-testid="user-row"
                data-user-id={user.user_id || user.id}
                style={styles.tr}
              >
                <td style={styles.td}>
                  <div style={styles.deviceName}>
                    {user.name || user.email}
                  </div>
                  <div style={styles.deviceId}>
                    {user.email}
                  </div>
                </td>

                <td style={styles.td}>
                  <span style={styles.rolePill}>
                    {user.role}
                  </span>
                </td>

                <td style={styles.td}>
                  {user.status || 'active'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Grants                                                                     */
/* -------------------------------------------------------------------------- */

function Grants({ orgId, session }) {
  const [grants, setGrants] = useState([]);
  const [users, setUsers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [showNew, setShowNew] = useState(false);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);

    try {
      const [grantResult, userResult, deviceResult] =
        await Promise.all([
          api(`/v1/orgs/${orgId}/grants`),
          api(`/v1/orgs/${orgId}/members`),
          api(`/v1/orgs/${orgId}/devices`),
        ]);

      setGrants(
        grantResult.grants ||
          grantResult.data ||
          []
      );

      setUsers(userResult.members || []);

      setDevices(deviceResult.devices || []);
    } catch {
      setGrants([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, [orgId]);

  if (loading) {
    return <LoadingState text="Loading grants…" />;
  }

  const canManage =
    session.role === 'owner' ||
    session.role === 'admin';

  return (
    <div>
      <PageIntro
        title="Permission grants"
        description="Explicit permission overrides resolved by the server."
        action={
          canManage ? (
            <button
              data-testid="new-grant"
              onClick={() => setShowNew(true)}
              style={styles.primaryButtonSmall}
            >
              + New grant
            </button>
          ) : null
        }
      />

      {showNew && (
        <GrantForm
          orgId={orgId}
          users={users}
          devices={devices}
          onClose={() => setShowNew(false)}
          onCreated={() => {
            setShowNew(false);
            load();
          }}
        />
      )}

      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>User</th>
              <th style={styles.th}>Permission</th>
              <th style={styles.th}>Device</th>
              <th style={styles.th}>Effect</th>
              <th style={styles.th}>Status</th>
            </tr>
          </thead>

          <tbody>
            {grants.map((grant) => {
              const permissions =
                grant.permissions ||
                grant.permission ||
                [];

              const list = Array.isArray(permissions)
                ? permissions
                : [permissions];

              return (
                <tr
                  key={grant.id}
                  data-testid="grant-row"
                  data-effect={grant.effect}
                  style={styles.tr}
                >
                  <td style={styles.td}>
                    {grant.userName ||
  grant.userEmail ||
  grant.userId}
                  </td>

                  <td style={styles.td}>
                    {list.join(', ')}
                  </td>

                  <td style={styles.td}>
                    {grant.deviceName ||
  grant.deviceId ||
  'All devices'}
                  </td>

                  <td style={styles.td}>
                    <span
                      style={{
                        ...styles.effectPill,
                        ...(grant.effect === 'deny'
                          ? styles.deny
                          : styles.allow),
                      }}
                    >
                      {grant.effect}
                    </span>
                  </td>

                  <td style={styles.td}>
                    {grant.expires_at
                      ? new Date(
                          grant.expires_at
                        ).toLocaleDateString()
                      : 'No expiry'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function GrantForm({
  orgId,
  users,
  devices,
  onClose,
  onCreated,
}) {
  const [userId, setUserId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [permissions, setPermissions] = useState([]);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

const [permissionOptions, setPermissionOptions] = useState([]);
useEffect(() => {
    async function loadPermissions() {
      try {
        const result = await api(`/v1/orgs/${orgId}/permissions`);
        setPermissionOptions(result.permissions || []);
      } catch (err) {
        setError(err.message);
        setPermissionOptions([]);
      }
    }

    loadPermissions();
  }, [orgId]);

  async function submit(event) {
    event.preventDefault();
    setError('');

    if (!userId || !permissions.length) {
      setError('Select a user and at least one permission.');
      return;
    }

    setSaving(true);

    try {
      await api(`/v1/orgs/${orgId}/grants`, {
        method: 'POST',
        body: JSON.stringify({
          userId,
          effect,
          permissions,
          deviceId: deviceId || null,
        }),
      });

      onCreated();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  function togglePermission(permission) {
    setPermissions((current) =>
      current.includes(permission)
        ? current.filter((item) => item !== permission)
        : [...current, permission]
    );
  }

  return (
    <form onSubmit={submit} style={styles.formCard}>
      <div style={styles.formHeader}>
        <div>
          <h3 style={styles.formTitle}>Create permission grant</h3>
          <p style={styles.muted}>
            The server validates whether you may grant each permission.
          </p>
        </div>

        <button
          type="button"
          onClick={onClose}
          style={styles.iconButton}
        >
          ×
        </button>
      </div>

      {error && <div style={styles.error}>{error}</div>}

      <label style={styles.label}>User</label>
      <select
        data-testid="grant-user"
        value={userId}
        onChange={(e) => setUserId(e.target.value)}
        style={styles.input}
      >
        <option value="">Select user</option>
        {users.map((user) => (
          <option
            key={user.user_id || user.id}
            value={user.user_id || user.id}
          >
            {user.name || user.email}
          </option>
        ))}
      </select>

      <label style={styles.label}>Device</label>
      <select
        data-testid="grant-device"
        value={deviceId}
        onChange={(e) => setDeviceId(e.target.value)}
        style={styles.input}
      >
        <option value="">All devices</option>
        {devices.map((device) => (
          <option key={device.id} value={device.id}>
            {device.name}
          </option>
        ))}
      </select>

      <label style={styles.label}>Effect</label>
      <select
        data-testid="grant-effect"
        value={effect}
        onChange={(e) => setEffect(e.target.value)}
        style={styles.input}
      >
        <option value="allow">allow</option>
        <option value="deny">deny</option>
      </select>

      <label style={styles.label}>Permissions</label>

      <div style={styles.permissionGrid}>
        {permissionOptions.map((permission) => (
          <label
            key={permission}
            style={styles.checkboxLabel}
          >
            <input
              type="checkbox"
              data-permission-key={permission}
              checked={permissions.includes(permission)}
              onChange={() =>
                togglePermission(permission)
              }
            />
            {permission}
          </label>
        ))}
      </div>

      <button
        data-testid="grant-submit"
        type="submit"
        style={styles.primaryButton}
      >
        {saving ? 'Creating…' : 'Create grant'}
      </button>
    </form>
  );
}

/* -------------------------------------------------------------------------- */
/* Sessions                                                                   */
/* -------------------------------------------------------------------------- */

function Sessions({ orgId }) {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api(`/v1/orgs/${orgId}/sessions`)
      .then((result) =>
        setSessions(result.sessions || [])
      )
      .catch(() => setSessions([]))
      .finally(() => setLoading(false));
  }, [orgId]);

  if (loading) {
    return <LoadingState text="Loading sessions…" />;
  }

  return (
    <div>
      <PageIntro
        title="Sessions"
        description="Remote sessions authorized for this organization."
      />

      <div style={styles.card}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Device</th>
              <th style={styles.th}>Mode</th>
              <th style={styles.th}>State</th>
              <th style={styles.th}>Started</th>
            </tr>
          </thead>

          <tbody>
            {sessions.map((session) => (
              <tr key={session.id} style={styles.tr}>
                <td style={styles.td}>
                  {session.device_id}
                </td>
                <td style={styles.td}>{session.mode}</td>
                <td style={styles.td}>{session.state}</td>
                <td style={styles.td}>
                  {session.started_at
                    ? new Date(
                        session.started_at
                      ).toLocaleString()
                    : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Audit                                                                      */
/* -------------------------------------------------------------------------- */

function Audit({ orgId }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api(`/v1/orgs/${orgId}/audit`)
      .then((result) =>
        setEvents(result.events || [])
      )
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  }, [orgId]);

  if (loading) {
    return <LoadingState text="Loading audit events…" />;
  }

  return (
    <div>
      <PageIntro
        title="Audit"
        description="Organization activity and authorization decisions."
      />

      <div style={styles.card}>
        {events.length === 0 ? (
          <div style={styles.empty}>
            <h3>No audit events</h3>
            <p>No events are currently available.</p>
          </div>
        ) : (
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Action</th>
                <th style={styles.th}>Actor</th>
                <th style={styles.th}>Result</th>
                <th style={styles.th}>Reason</th>
                <th style={styles.th}>Time</th>
              </tr>
            </thead>

            <tbody>
              {events.map((event) => (
                <tr key={event.id} style={styles.tr}>
                  <td style={styles.td}>
                    {event.action}
                  </td>
                  <td style={styles.td}>
                    {event.actor_id}
                  </td>
                  <td style={styles.td}>
                    {event.result}
                  </td>
                  <td style={styles.td}>
                    {event.reason_code || '—'}
                  </td>
                  <td style={styles.td}>
                    {event.at
                      ? new Date(event.at).toLocaleString()
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Admin                                                                      */
/* -------------------------------------------------------------------------- */

function Admin({ orgId, role }) {
  const [name, setName] = useState('');
  const [saved, setSaved] = useState(false);

  const isOwner = role === 'owner';
  async function deleteOrganization() {
  const confirmed = window.confirm(
    'Delete this organization? This action cannot be undone.'
  );

  if (!confirmed) return;

  try {
    await api(`/v1/orgs/${orgId}`, {
      method: 'DELETE',
    });

    window.location.href = '/';
  } catch (err) {
    window.alert(err.message || 'Failed to delete organization.');
  }
}

  async function renameOrganization() {
    if (!name.trim()) return;

    try {
      await api(`/v1/orgs/${orgId}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: name.trim(),
        }),
      });

      setSaved(true);
    } catch {
      setSaved(false);
    }
  }

  return (
    <div>
      <PageIntro
        title="Administration"
        description="Organization-level configuration."
      />

      <div style={styles.adminGrid}>
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <h3 style={styles.cardTitle}>Organization identity</h3>
            <span style={styles.rolePill}>{role}</span>
          </div>

          <label style={styles.label}>
            Organization name
          </label>

          <input
            data-testid="rename-org"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setSaved(false);
            }}
            placeholder="New organization name"
            style={styles.input}
          />

          <button
            onClick={renameOrganization}
            style={styles.primaryButtonSmall}
          >
            Rename organization
          </button>

          {saved && (
            <div style={styles.success}>
              Organization updated.
            </div>
          )}
        </div>

        {isOwner && (
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <h3 style={styles.cardTitle}>
                Organization ownership
              </h3>
            </div>

            <p style={styles.muted}>
              Owner-only organization actions are available
              here.
            </p>

            <button
  data-testid="delete-org"
  onClick={deleteOrganization}
  style={styles.dangerButton}
>
  Delete organization
</button>
          </div>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Invite                                                                     */
/* -------------------------------------------------------------------------- */

function InvitePage({ token }) {
  const [invite, setInvite] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [name, setName] = useState('');
  const [password, setPassword] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [accepted, setAccepted] = useState(false);

  useEffect(() => {
    loadInvite();
  }, [token]);

  async function loadInvite() {
    setLoading(true);
    setError('');

    try {
      const result = await api(
        `/v1/invites/${encodeURIComponent(token)}`
      );

      setInvite(result);
    } catch (err) {
      setError(err.message || 'Invite not found.');
    } finally {
      setLoading(false);
    }
  }

  async function submit(event) {
    event.preventDefault();
    setError('');

    if (!name.trim() || !password) {
      setError('Please enter your name and password.');
      return;
    }

    setSubmitting(true);

    try {
      await api(
        `/v1/invites/${encodeURIComponent(token)}/accept`,
        {
          method: 'POST',
          body: JSON.stringify({
            name: name.trim(),
            password,
          }),
        }
      );

      window.location.href = '/';
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <main style={styles.centerPage}>
        <div style={styles.loadingCard}>
          Loading invitation…
        </div>
      </main>
    );
  }

  if (error || !invite) {
    return (
      <main style={styles.centerPage}>
        <div
          data-testid="invite-error"
          style={styles.errorCard}
        >
          <div style={styles.errorIcon}>!</div>
          <h1>Invitation unavailable</h1>
          <p>{error || 'Invite not found.'}</p>
        </div>
      </main>
    );
  }

  if (accepted) {
    return (
      <main style={styles.centerPage}>
        <div style={styles.successCard}>
          <div style={styles.successIcon}>✓</div>
          <h1>Invitation accepted</h1>
          <p>Your account has been created successfully.</p>

          <button
            onClick={() => {
              window.location.href = '/';
            }}
            style={styles.primaryButton}
          >
            Continue to sign in
          </button>
        </div>
      </main>
    );
  }

  return (
    <main style={styles.loginPage}>
      <form onSubmit={submit} style={styles.loginCard}>
        <div style={styles.brandMark}>R</div>
        <div style={styles.eyebrow}>REMOTEOPS</div>

        <h1 style={styles.loginTitle}>
          You&apos;re invited
        </h1>

        <p style={styles.muted}>
          Join <strong>{invite.orgName}</strong> as{' '}
          <strong data-testid="invite-role">
            {invite.role}
          </strong>
          .
        </p>

        <label style={styles.label}>Email</label>
        <input
          data-testid="invite-email"
          value={invite.email}
          readOnly
          style={styles.input}
        />

        <label style={styles.label}>Name</label>
        <input
          data-testid="invite-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Your name"
          style={styles.input}
        />

        <label style={styles.label}>Password</label>
        <input
          data-testid="invite-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          type="password"
          placeholder="At least 8 characters"
          style={styles.input}
        />

        {error && (
          <div style={styles.error}>{error}</div>
        )}

        <button
          data-testid="invite-submit"
          type="submit"
          style={styles.primaryButton}
        >
          {submitting
            ? 'Creating account…'
            : 'Accept invitation'}
        </button>
      </form>
    </main>
  );
}

/* -------------------------------------------------------------------------- */
/* Small components                                                           */
/* -------------------------------------------------------------------------- */

function PageIntro({ title, description, action }) {
  return (
    <div style={styles.pageIntro}>
      <div>
        <h2 style={styles.sectionTitle}>{title}</h2>
        <p style={styles.sectionDescription}>
          {description}
        </p>
      </div>

      {action}
    </div>
  );
}

function LoadingState({ text }) {
  return (
    <div style={styles.empty}>
      <div style={styles.spinner}>◌</div>
      <p>{text}</p>
    </div>
  );
}

function ErrorState({ message }) {
  return (
    <div style={styles.errorCard}>
      <h3>Unable to load this section</h3>
      <p>{message}</p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Styles                                                                     */
/* -------------------------------------------------------------------------- */

const styles = {
  shell: {
    minHeight: '100vh',
    display: 'flex',
    fontFamily:
      'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    color: '#172033',
  },

  sidebar: {
    width: 250,
    minHeight: '100vh',
    color: '#fff',
    display: 'flex',
    flexDirection: 'column',
    padding: 22,
    boxSizing: 'border-box',
  },

  sidebarBrand: {
    display: 'flex',
    gap: 12,
    alignItems: 'center',
    marginBottom: 32,
  },

  sidebarLogo: {
    width: 38,
    height: 38,
    borderRadius: 11,
    background: '#fff',
    color: '#172a50',
    display: 'grid',
    placeItems: 'center',
    fontWeight: 900,
    fontSize: 20,
  },

  sidebarTitle: {
    fontWeight: 800,
    fontSize: 16,
  },

  sidebarSubtitle: {
    opacity: 0.55,
    fontSize: 11,
    marginTop: 2,
  },

  sidebarLabel: {
    fontSize: 10,
    fontWeight: 800,
    letterSpacing: 1.2,
    opacity: 0.45,
    marginBottom: 8,
  },

  orgSection: {
    marginBottom: 24,
  },

  orgButton: {
    width: '100%',
    border: 0,
    color: '#fff',
    borderRadius: 9,
    padding: '10px 11px',
    display: 'flex',
    gap: 9,
    alignItems: 'center',
    cursor: 'pointer',
    textAlign: 'left',
    marginBottom: 3,
  },

  orgDot: {
    width: 7,
    height: 7,
    borderRadius: '50%',
    background: '#76a9ff',
  },

  createOrgButton: {
    width: '100%',
    marginTop: 8,
    border: '1px dashed rgba(255,255,255,.28)',
    background: 'transparent',
    color: 'rgba(255,255,255,.75)',
    borderRadius: 9,
    padding: 9,
    cursor: 'pointer',
  },

  nav: {
    display: 'grid',
    gap: 5,
  },

  navButton: {
    border: 0,
    background: 'transparent',
    color: 'rgba(255,255,255,.67)',
    padding: '11px 12px',
    borderRadius: 9,
    cursor: 'pointer',
    display: 'flex',
    gap: 12,
    alignItems: 'center',
    textAlign: 'left',
    fontSize: 14,
  },

  navButtonActive: {
    background: 'rgba(255,255,255,.13)',
    color: '#fff',
  },

  sidebarFooter: {
    marginTop: 'auto',
    borderTop: '1px solid rgba(255,255,255,.12)',
    paddingTop: 16,
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },

  userAvatar: {
    width: 32,
    height: 32,
    borderRadius: '50%',
    background: 'rgba(255,255,255,.16)',
    display: 'grid',
    placeItems: 'center',
    fontWeight: 800,
  },

  footerName: {
    fontSize: 13,
    fontWeight: 700,
    maxWidth: 150,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },

  footerRole: {
    fontSize: 11,
    opacity: 0.55,
    marginTop: 2,
    textTransform: 'capitalize',
  },

  main: {
    flex: 1,
    minWidth: 0,
  },

  header: {
    minHeight: 88,
    background: 'rgba(255,255,255,.82)',
    borderBottom: '1px solid rgba(20,35,60,.08)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 34px',
    boxSizing: 'border-box',
  },

  breadcrumb: {
    fontSize: 10,
    letterSpacing: 1.2,
    fontWeight: 800,
    color: '#7c879b',
    marginBottom: 4,
  },

  pageTitle: {
    margin: 0,
    fontSize: 24,
    letterSpacing: -0.6,
  },

  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
  },

  content: {
    padding: 32,
    maxWidth: 1250,
    margin: '0 auto',
  },

  pageIntro: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-end',
    gap: 20,
    marginBottom: 22,
  },

  sectionTitle: {
    margin: 0,
    fontSize: 20,
  },

  sectionDescription: {
    margin: '5px 0 0',
    color: '#6d7789',
    fontSize: 14,
  },

  card: {
    background: '#fff',
    border: '1px solid #e3e8f0',
    borderRadius: 15,
    boxShadow: '0 5px 20px rgba(25,40,70,.045)',
    overflow: 'hidden',
  },

  cardHeader: {
    padding: 20,
    borderBottom: '1px solid #edf0f5',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },

  cardTitle: {
    margin: 0,
    fontSize: 16,
  },

  table: {
    width: '100%',
    borderCollapse: 'collapse',
  },

  th: {
    padding: '13px 18px',
    textAlign: 'left',
    fontSize: 10,
    textTransform: 'uppercase',
    letterSpacing: 0.8,
    color: '#7a8495',
    background: '#f8fafc',
    borderBottom: '1px solid #e8edf3',
  },

  tr: {
    borderBottom: '1px solid #edf0f4',
  },

  td: {
    padding: '15px 18px',
    fontSize: 13,
    verticalAlign: 'middle',
  },

  deviceName: {
    fontWeight: 700,
  },

  deviceId: {
    fontSize: 11,
    color: '#8a94a5',
    marginTop: 3,
  },

  typePill: {
    display: 'inline-block',
    padding: '4px 8px',
    borderRadius: 7,
    background: '#f1f4f8',
    color: '#596477',
    fontSize: 11,
  },

  status: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 12,
    fontWeight: 600,
  },

  statusOnline: {
    color: '#168052',
  },

  statusOffline: {
    color: '#7b8492',
  },

  statusDot: {
    width: 7,
    height: 7,
    borderRadius: '50%',
    background: 'currentColor',
  },

  actionRow: {
    display: 'flex',
    gap: 6,
    flexWrap: 'wrap',
  },

  smallButton: {
    border: '1px solid #d8e0eb',
    background: '#fff',
    color: '#26364f',
    borderRadius: 7,
    padding: '6px 9px',
    cursor: 'pointer',
    fontSize: 11,
    fontWeight: 700,
  },

  primaryButton: {
    width: '100%',
    border: 0,
    background: '#2563eb',
    color: '#fff',
    borderRadius: 9,
    padding: '12px 15px',
    cursor: 'pointer',
    fontWeight: 800,
    fontSize: 14,
    marginTop: 8,
  },

  primaryButtonSmall: {
    border: 0,
    background: '#2563eb',
    color: '#fff',
    borderRadius: 8,
    padding: '9px 13px',
    cursor: 'pointer',
    fontWeight: 800,
    fontSize: 12,
  },

  dangerButton: {
    border: 0,
    background: '#fee2e2',
    color: '#b42318',
    borderRadius: 8,
    padding: '10px 13px',
    cursor: 'pointer',
    fontWeight: 800,
    marginTop: 12,
  },

  rolePill: {
    display: 'inline-block',
    padding: '5px 9px',
    borderRadius: 7,
    background: '#eef2ff',
    color: '#4338ca',
    fontSize: 11,
    fontWeight: 800,
    textTransform: 'capitalize',
  },

  effectPill: {
    display: 'inline-block',
    padding: '5px 9px',
    borderRadius: 7,
    fontSize: 11,
    fontWeight: 800,
    textTransform: 'uppercase',
  },

  allow: {
    background: '#dcfce7',
    color: '#166534',
  },

  deny: {
    background: '#fee2e2',
    color: '#991b1b',
  },

  empty: {
    background: 'rgba(255,255,255,.75)',
    border: '1px dashed #d5dce7',
    borderRadius: 15,
    padding: 60,
    textAlign: 'center',
    color: '#737e90',
  },

  emptyIcon: {
    fontSize: 32,
    opacity: 0.4,
  },

  spinner: {
    fontSize: 28,
  },

  muted: {
    color: '#727d8f',
    fontSize: 13,
  },

  error: {
    background: '#fff1f2',
    border: '1px solid #fecdd3',
    color: '#9f1239',
    padding: 10,
    borderRadius: 8,
    fontSize: 13,
    marginBottom: 12,
  },

  globalError: {
    margin: '16px 32px 0',
    padding: '11px 14px',
    borderRadius: 9,
    background: '#fff1f2',
    border: '1px solid #fecdd3',
    color: '#9f1239',
    cursor: 'pointer',
  },

  formCard: {
    background: '#fff',
    border: '1px solid #dce3ed',
    borderRadius: 15,
    padding: 22,
    marginBottom: 20,
    boxShadow: '0 5px 20px rgba(25,40,70,.05)',
  },

  formHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 20,
  },

  formTitle: {
    margin: 0,
    fontSize: 17,
  },

  iconButton: {
    border: 0,
    background: '#f1f4f8',
    width: 30,
    height: 30,
    borderRadius: 7,
    cursor: 'pointer',
    fontSize: 18,
  },

  label: {
    display: 'block',
    fontSize: 12,
    fontWeight: 800,
    color: '#495568',
    marginBottom: 6,
    marginTop: 13,
  },

  input: {
    width: '100%',
    boxSizing: 'border-box',
    border: '1px solid #d8e0ea',
    borderRadius: 8,
    padding: '10px 11px',
    fontSize: 13,
    outline: 'none',
    background: '#fff',
  },

  permissionGrid: {
    display: 'grid',
    gridTemplateColumns:
      'repeat(auto-fit, minmax(190px, 1fr))',
    gap: 8,
    marginBottom: 15,
  },

  checkboxLabel: {
    border: '1px solid #e1e6ee',
    borderRadius: 8,
    padding: 10,
    display: 'flex',
    gap: 8,
    alignItems: 'center',
    fontSize: 12,
    cursor: 'pointer',
  },

  adminGrid: {
    display: 'grid',
    gridTemplateColumns:
      'repeat(auto-fit, minmax(300px, 1fr))',
    gap: 18,
  },

  success: {
    color: '#166534',
    background: '#dcfce7',
    padding: 9,
    borderRadius: 8,
    fontSize: 12,
    marginTop: 12,
  },

  loginPage: {
    minHeight: '100vh',
    background:
      'linear-gradient(135deg, #eef4ff 0%, #f8fafc 55%, #eef2ff 100%)',
    display: 'grid',
    placeItems: 'center',
    padding: 20,
    boxSizing: 'border-box',
    fontFamily:
      'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  },

  loginCard: {
    width: '100%',
    maxWidth: 420,
    background: '#fff',
    border: '1px solid #e2e8f0',
    borderRadius: 18,
    padding: 32,
    boxSizing: 'border-box',
    boxShadow: '0 20px 60px rgba(30,50,90,.1)',
  },

  brandMark: {
    width: 46,
    height: 46,
    borderRadius: 13,
    background: '#2563eb',
    color: '#fff',
    display: 'grid',
    placeItems: 'center',
    fontSize: 22,
    fontWeight: 900,
    marginBottom: 18,
  },

  eyebrow: {
    color: '#2563eb',
    fontSize: 10,
    fontWeight: 900,
    letterSpacing: 1.5,
  },

  loginTitle: {
    margin: '5px 0 7px',
    fontSize: 27,
    letterSpacing: -0.7,
  },

  centerPage: {
    minHeight: '100vh',
    display: 'grid',
    placeItems: 'center',
    background: '#f5f7fb',
    fontFamily:
      'Inter, ui-sans-serif, system-ui, sans-serif',
  },

  loadingCard: {
    background: '#fff',
    padding: 25,
    borderRadius: 13,
    border: '1px solid #e1e7ef',
  },

  errorCard: {
    background: '#fff',
    padding: 30,
    maxWidth: 450,
    borderRadius: 15,
    border: '1px solid #fecdd3',
    color: '#7f1d1d',
    textAlign: 'center',
  },

  successCard: {
    background: '#fff',
    padding: 32,
    maxWidth: 450,
    borderRadius: 15,
    border: '1px solid #bbf7d0',
    color: '#14532d',
    textAlign: 'center',
  },

  errorIcon: {
    width: 42,
    height: 42,
    margin: '0 auto 12px',
    borderRadius: '50%',
    background: '#fee2e2',
    display: 'grid',
    placeItems: 'center',
    fontWeight: 900,
  },

  successIcon: {
    width: 42,
    height: 42,
    margin: '0 auto 12px',
    borderRadius: '50%',
    background: '#dcfce7',
    display: 'grid',
    placeItems: 'center',
    fontWeight: 900,
  },

  
};

createRoot(document.getElementById('root')).render(<App />);