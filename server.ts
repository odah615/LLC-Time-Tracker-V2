import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// CORS headers for desktop software and cross-origin clients
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ==========================================
// CENTRAL PERSISTENCE & CRYPTO
// ==========================================
const SYNC_BRIDGE_FILE = path.join(process.cwd(), '.sync_bridge.json');

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return `pbkdf2:sha512:10000:${salt}:${hash}`;
}

export function verifyPassword(password: string, storedHashOrPlain?: string): boolean {
  if (!storedHashOrPlain) return false;
  const trimmed = storedHashOrPlain.trim();
  if (trimmed.startsWith('pbkdf2:')) {
    const parts = trimmed.split(':');
    if (parts.length === 5) {
      const iterations = parseInt(parts[2], 10);
      const salt = parts[3];
      const originalHash = parts[4];
      const computed = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512').toString('hex');
      return computed === originalHash;
    }
  }
  // Fallback for legacy plain text entries during migration
  return trimmed === password;
}

export function sanitizeUser(user: any): any {
  if (!user || typeof user !== 'object') return null;
  const { password, passwordHash, ...safe } = user;
  return safe;
}

const DEFAULT_DESIGNATION_TASKS: Record<string, string[]> = {
  'Outbound Agent/Team': [
    'Data Entry & Market Research',
    'Email Reachout',
    'Follow-up',
    'Training',
    'Team Meeting',
    'Coaching',
  ],
  'Inbound Agent/Team': [
    'Email Interaction',
    'Training',
    'Team Meeting',
    'Coaching',
  ],
  'Agent': [
    'Data Entry & Market Research',
    'Email Reachout',
    'Email Interaction',
    'Follow-up',
    'Training',
    'Team Meeting',
    'Coaching',
  ],
  'Team Leader': [
    'Team Supervision',
    'Team Meeting',
    'Training',
    'Coaching',
    'QA Review',
    'On Shift',
  ],
  'Trainer': [
    'Training',
    'Coaching',
    'Team Meeting',
    'QA Review',
    'On Shift',
  ],
  'Admin': [
    'System Ops Review',
    'On Shift',
  ],
  'Super Admin': [
    'System Ops Review',
    'On Shift',
  ],
  'QA Specialist': [
    'QA Email Audit',
    'Other QA Reviews',
    'QA Coaching',
  ],
  'Writer': [
    'Content Writing',
    'Team Meeting',
    'On Shift',
  ],
  'HR': [
    'Team Meeting',
    'HR & Recruitment',
    'Payroll Task',
    'On Shift',
  ],
  'Payroll Officer': [
    'Payroll Task',
    'On Shift',
    'Team Meeting',
  ],
};

const DEFAULT_ROLE_PERMISSIONS: Record<string, any> = {
  admin: {
    canEditEmployees: true,
    canAssignTeamLeader: true,
    canViewActivityLogs: true,
    canViewScreenshots: true,
    canViewTimesheets: true,
    canViewPayroll: true,
    canManageTasks: true,
    canManageRoles: true,
    canSyncSheets: true,
  },
  trainer: {
    canEditEmployees: true,
    canAssignTeamLeader: true,
    canViewActivityLogs: true,
    canViewScreenshots: true,
    canViewTimesheets: true,
    canViewPayroll: false,
    canManageTasks: true,
    canManageRoles: false,
    canSyncSheets: false,
  },
  team_lead: {
    canEditEmployees: false,
    canAssignTeamLeader: true,
    canViewActivityLogs: true,
    canViewScreenshots: true,
    canViewTimesheets: true,
    canViewPayroll: false,
    canManageTasks: false,
    canManageRoles: false,
    canSyncSheets: false,
  },
  hr: {
    canEditEmployees: true,
    canAssignTeamLeader: false,
    canViewActivityLogs: false,
    canViewScreenshots: false,
    canViewTimesheets: true,
    canViewPayroll: false,
    canManageTasks: false,
    canManageRoles: false,
    canSyncSheets: false,
  },
  payroll: {
    canEditEmployees: false,
    canAssignTeamLeader: false,
    canViewActivityLogs: false,
    canViewScreenshots: false,
    canViewTimesheets: true,
    canViewPayroll: true,
    canManageTasks: false,
    canManageRoles: false,
    canSyncSheets: false,
  },
  agent: {
    canEditEmployees: false,
    canAssignTeamLeader: false,
    canViewActivityLogs: false,
    canViewScreenshots: false,
    canViewTimesheets: false,
    canViewPayroll: false,
    canManageTasks: false,
    canManageRoles: false,
    canSyncSheets: false,
  },
};

interface BridgeData {
  presence: Record<string, any>;
  timelogs: any[];
  users: any[];
  attendance: any[];
  auditlogs: any[];
  tasks: Record<string, string[]>;
  permissions: Record<string, any>;
  config: { webhookUrl?: string; spreadsheetId?: string };
}

const PROHIBITED_PRODUCTION_MARKERS = [
  'AKfycbyKGMOWV0u5xcv_lOKBk6LXpbjrlgZiuqtCs3_HbqjekoJZdXpdfA_1kDjP7H0ulLsw3Q',
  '1h8ssmDEcV-PMGlkpOzfQCtlRpnoT0CBQQveT3e4wPfA',
];

export function isProhibitedProductionTarget(target?: string | null): boolean {
  if (!target) return false;
  const str = String(target);
  return PROHIBITED_PRODUCTION_MARKERS.some((m) => str.includes(m));
}

let bridgeState: BridgeData = {
  presence: {},
  timelogs: [],
  users: [],
  attendance: [],
  auditlogs: [],
  tasks: DEFAULT_DESIGNATION_TASKS,
  permissions: DEFAULT_ROLE_PERMISSIONS,
  config: {
    webhookUrl: process.env.SANDBOX_APPS_SCRIPT_URL || '',
    spreadsheetId: '',
  },
};

// Canonical staff resolver
const CANONICAL_STAFF: Record<string, string> = {
  'SUPERADMIN': 'Admin',
  'LLC-0001': 'Agent_Admin',
  'LLC-0002': 'Team_Leader1',
  'LLC-0003': 'Pia',
  'LLC-0004': 'Alexa Gabrielle Bardaje',
  'LLC-0005': 'April Sam Dimaano',
  'LLC-0006': 'Boris Andrew Villanueva',
  'LLC-0007': 'Cyril Diola Garcia',
  'LLC-0008': 'Daina Yanez',
  'LLC-0009': 'Fatima Dence David',
  'LLC-0010': 'Gerald A. Salvador',
  'LLC-0011': 'Jayson Cariaga',
  'LLC-0012': 'Jenalyn Nueva',
  'LLC-0013': 'Kathleen Ann L. Totaan',
  'LLC-0014': 'Lourdes Mary Cenina',
  'LLC-0015': 'Luis David Ramirez',
  'LLC-0016': 'Maria Racquel Gracia M. Libarios',
  'LLC-0017': 'Mark Jesus A. Egoy',
  'LLC-0018': 'Raquel Guiapal',
  'LLC-0019': 'Ron Louie Logan',
  'LLC-0020': 'Rubilyne Barrameda',
  'LLC-0021': 'Shiela Romey',
  'LLC-0022': 'Trixy Ashley Decena Mabutol',
  'LLC-0023': 'Juan David',
  'LLC-0024': 'Carl',
  'LLC-0025': 'Lyanne',
  'LLC-0026': 'Allen',
  'LLC-0027': 'Bryan',
  'LLC-0028': 'Test Agent',
  'LLC-0029': 'Kyra',
  'LLC-0030': 'Hosen',
  'LLC-0031': 'Danah',
  'LLC-0032': 'Miko Carmel',
  'LLC-0033': 'Jocelyn Enriquez',
  'LLC-0034': 'Omar Apolinario',
  'LLC-0035': 'John Gabriel Pai',
  'LLC-0036': 'Amy Janine Pedrito',
  'LLC-0037': 'Nicole Alcantara',
  'LLC-0038': 'Chessa Mae Ful',
  'LLC-0039': 'Myra Balatbat',
  'LLC-0040': 'John Cedric San',
  'LLC-0041': 'Jhureza Lazo',
  'LLC-0042': 'Orpha Percy',
  'LLC-0043': 'Judy',
  'LLC-0044': 'Ann Abad',
  'LLC-0045': 'Aiza Gonzales',
  'LLC-0049': 'Paolo Leanillo',
  'LLC-0052': 'Gley Alday',
  'LLC-0053': 'Paul Jeffrey Bulosan',
  'LLC-0055': 'Mae Frances',
  'LLC-0056': 'Leslie Timog',
  'LLC-0057': 'Almark Debuque',
  'LLC-0058': 'John Calvin Natividad',
  'LLC-0059': 'Queenie Mae Engbino',
  'LLC-0060': 'Justine Hiceta',
  'LLC-0061': 'Patricia Elizon',
  'LLC-0062': 'Annalyn Alforque',
  'LLC-0063': 'Beinalyn Dianala',
  'LLC-0064': 'Deny Datiles',
  'LLC-0065': 'Jean Cristine Serdea',
  'LLC-0066': 'Patrick Guardian',
  'LLC-0069': 'Princess Nicole Regala',
  'LLC-0070': 'Rodolfo Peralta Jr',
  'LLC-0071': 'Princess Loto',
  'LLC-0072': 'Mechill Barredo',
  'LLC-0073': 'Ejay Suaze',
  'LLC-0074': 'Marvin Garcia',
  'LLC-0075': 'Rexcell Remocaldo',
  'LLC-0076': 'Kristeen Liquit',
  'LLC-0077': 'Ma. Fedelyn Rapiz',
  'LLC-0078': 'Maria Paula Nabo',
  'LLC-0079': 'Moneque Belarmino',
  'LLC-0080': 'Rain Machado',
  'LLC-0081': 'Suzette Apordo',
  'LLC-0082': 'Geraldine Grajo',
  'LLC-0083': 'Jasmine Joyce Lucena',
  'LLC-0084': 'Mike Rapiz',
  'LLC-0085': 'Princess Yara Mustapha',
  'LLC-0086': 'Gracious Yvonne Batarra',
  'LLC-0087': 'Miya Pearl Pricas',
  'LLC-0088': 'Jera Mae Millan',
  'LLC-0089': 'Charie Ceniza',
  'LLC-0090': 'Jeramil Vegilla',
  'LLC-0091': 'Julius Cabrera',
  'LLC-0092': 'Aubrey Dela Cruz',
  'LLC-0093': 'Ayessa Balondo',
  'PBULOSAN': 'Paul Jeffrey Bulosan',
  'LLC-0101': 'Junaisa Dianne Ramos',
  'LLC-0102': 'Jessa Fuentes',
  'LLC-0103': 'Rowena Vegilla',
  'LLC-0104': 'Toni Mitchell Villoso',
  'LLC-0105': 'Y. Obiedo',
  'LLC-0106': 'Camille',
  'LLC-0107': 'Juan Carlo Yamzon',
  'LLC-0108': 'Kris Simpson',
  'LLC-0109': 'Esperanza Bacalla',
  'LLC-0110': 'Albert Monfero',
  'LLC-0111': 'Rochelle Ebit',
  'LLC-0112': 'Irish Jane Paz',
  'LLC-0113': 'Jessica Algones',
  'LLC-0114': 'Chamille Enriquez',
  'LLC-0115': 'Maria Leatrice Laderas',
  'LLC-0116': 'Michellenie Mae Yntela',
  'LLC-0120': 'Niña Carmella Domingo',
  'LLC-0121': 'Ayra Erika Sy',
  'LLC-0122': 'Bian Labares Maglangit',
};

const resolveStaffName = (code?: string, username?: string, name?: string, id?: string): string => {
  const n = (name || '').trim();
  if (n && n !== 'Unknown' && n !== 'Employee' && n !== 'Staff' && n !== 'Agent') {
    return n;
  }
  const c = (code || '').toUpperCase().trim();
  const num = c.replace(/^[A-Z\-_]+/, '');
  for (const [k, v] of Object.entries(CANONICAL_STAFF)) {
    const kNum = k.replace(/^[A-Z\-_]+/, '');
    if (c === k || (num && kNum && num === kNum)) return v;
  }
  const u = (username || '').toLowerCase().trim();
  if (u === 'admin' || c === 'SUPERADMIN') return 'Admin';
  if (u === 'trainer' || c === 'LLC-0003') return 'Pia';
  return n || username || 'Employee';
};

// Load initial bridge state if exists
try {
  if (fs.existsSync(SYNC_BRIDGE_FILE)) {
    const raw = fs.readFileSync(SYNC_BRIDGE_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      const sanitizedUsers = Array.isArray(parsed.users)
        ? parsed.users.map((u: any) => {
            const hasChanged = u.isPasswordChanged === 'YES' || (!u.mustChangePassword && u.password && u.password !== 'Password123!');
            return {
              ...u,
              name: resolveStaffName(u.employeeCode, u.username, u.name, u.id),
              isPasswordChanged: hasChanged ? 'YES' : (u.isPasswordChanged || 'NO'),
              mustChangePassword: hasChanged ? false : (u.mustChangePassword ?? true),
              passwordHash: u.passwordHash || (u.password ? hashPassword(u.password) : hashPassword('Password123!')),
            };
          })
        : [];

      const sanitizedPresence: Record<string, any> = {};
      if (parsed.presence && typeof parsed.presence === 'object') {
        for (const [k, v] of Object.entries(parsed.presence)) {
          if (v && typeof v === 'object') {
            const p = v as any;
            sanitizedPresence[k] = {
              ...p,
              userName: resolveStaffName(p.employeeCode, p.userName, p.userName, p.userId),
            };
          }
        }
      }

      bridgeState = {
        presence: sanitizedPresence,
        timelogs: Array.isArray(parsed.timelogs) ? parsed.timelogs : [],
        users: sanitizedUsers,
        attendance: Array.isArray(parsed.attendance) ? parsed.attendance : [],
        auditlogs: Array.isArray(parsed.auditlogs) ? parsed.auditlogs : [],
        tasks: parsed.tasks && typeof parsed.tasks === 'object' ? { ...DEFAULT_DESIGNATION_TASKS, ...parsed.tasks } : DEFAULT_DESIGNATION_TASKS,
        permissions: parsed.permissions && typeof parsed.permissions === 'object' ? { ...DEFAULT_ROLE_PERMISSIONS, ...parsed.permissions } : DEFAULT_ROLE_PERMISSIONS,
        config: {
          webhookUrl: (parsed.config?.webhookUrl && !isProhibitedProductionTarget(parsed.config.webhookUrl))
            ? parsed.config.webhookUrl
            : (process.env.SANDBOX_APPS_SCRIPT_URL || ''),
          spreadsheetId: (parsed.config?.spreadsheetId && !isProhibitedProductionTarget(parsed.config.spreadsheetId))
            ? parsed.config.spreadsheetId
            : '',
        },
      };
    }
  }
} catch (e) {
  console.warn('[Bridge] Error loading bridge file:', e);
}

let saveDebounceTimer: any = null;
const persistBridgeState = () => {
  if (saveDebounceTimer) clearTimeout(saveDebounceTimer);
  saveDebounceTimer = setTimeout(() => {
    try {
      fs.writeFileSync(SYNC_BRIDGE_FILE, JSON.stringify(bridgeState, null, 2), 'utf-8');
    } catch (e) {
      console.warn('[Bridge] Error saving bridge file:', e);
    }
  }, 1000);
};

// Periodic stale presence cleanup (3 minutes without heartbeat)
const cleanStalePresence = () => {
  const now = Date.now();
  let changed = false;
  for (const [userId, p] of Object.entries(bridgeState.presence)) {
    if (p && p.isOnline) {
      const lastHbMs = p.lastHeartbeat ? new Date(p.lastHeartbeat).getTime() : 0;
      const timeoutMs = p.isTracking ? 180000 : 90000;
      if (lastHbMs > 0 && now - lastHbMs > timeoutMs) {
        bridgeState.presence[userId] = {
          ...p,
          isOnline: false,
          status: 'offline',
          isTracking: false,
          isPaused: false,
          currentTask: 'Shift Concluded',
          currentApp: 'None',
        };
        changed = true;
      }
    }
  }
  if (changed) persistBridgeState();
};

setInterval(cleanStalePresence, 10000);

async function forwardToAppsScript(action: string, payload: any) {
  const webhookUrl = (bridgeState.config.webhookUrl || process.env.SANDBOX_APPS_SCRIPT_URL || '').trim();
  if (!webhookUrl || !webhookUrl.startsWith('https://script.google.com/macros/s/')) return;
  if (isProhibitedProductionTarget(webhookUrl)) return;

  try {
    const body = {
      ...payload,
      action,
      secret: process.env.SANDBOX_APPS_SCRIPT_SECRET || '',
    };
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    });
  } catch (err: any) {
    console.warn(`[Forward AppsScript ${action}] Notice:`, err?.message || err);
  }
}

// ==========================================
// API ROUTES
// ==========================================

// Health Check
app.get('/api/health', (req, res) => {
  cleanStalePresence();
  const onlineCount = Object.values(bridgeState.presence).filter((p: any) => p?.isOnline).length;
  const trackingCount = Object.values(bridgeState.presence).filter((p: any) => p?.isOnline && p?.isTracking).length;
  res.json({
    status: 'ok',
    serverTime: new Date().toISOString(),
    onlineUsers: onlineCount,
    trackingUsers: trackingCount,
    totalRegisteredUsers: bridgeState.users.length,
    timelogsCount: bridgeState.timelogs.length,
  });
});

// Authentication: Login Endpoint
app.post('/api/auth/login', (req, res) => {
  const { usernameOrCode, password } = req.body || {};
  if (!usernameOrCode || !password) {
    return res.status(400).json({ success: false, error: 'Username/Code and password are required' });
  }

  const query = String(usernameOrCode).trim().toLowerCase();
  const cleanUser = query.replace(/^@/, '');
  const cleanDigits = query.replace(/\D/g, '');

  const foundUser = bridgeState.users.find((u) => {
    const uCode = String(u.employeeCode || '').toLowerCase();
    const uUser = String(u.username || '').toLowerCase();
    const uDigits = uCode.replace(/\D/g, '');
    if (uCode === query || uUser === cleanUser) return true;
    if (cleanDigits && uDigits && uDigits === cleanDigits) return true;
    if (u.id?.toLowerCase() === query || u.email?.toLowerCase() === query) return true;
    return false;
  });

  if (!foundUser) {
    return res.status(401).json({ success: false, error: `Account not found for "${usernameOrCode}"` });
  }

  const isRootAdmin =
    foundUser.role === 'admin' ||
    foundUser.employeeCode?.toLowerCase() === 'superadmin' ||
    foundUser.id === 'usr-superadmin-red';

  const storedHash = foundUser.passwordHash || (foundUser.password ? hashPassword(foundUser.password) : '');
  const isPwChanged = foundUser.isPasswordChanged === 'YES';

  let isValid = false;
  if (isPwChanged) {
    isValid = verifyPassword(password, storedHash) || (foundUser.password ? password === foundUser.password : false);
  } else {
    isValid =
      password === 'Password123!' ||
      verifyPassword(password, storedHash) ||
      (foundUser.password ? password === foundUser.password : false) ||
      (isRootAdmin && (password === 'AdminpassW0rd123!' || password === 'AdminpassWord123!' || password === 'SUPERADMIN2026'));
  }

  if (!isValid) {
    return res.status(401).json({ success: false, error: 'Incorrect password.' });
  }

  const mustChange = !isRootAdmin && (!isPwChanged || password === 'Password123!' || foundUser.mustChangePassword);

  res.json({
    success: true,
    user: sanitizeUser(foundUser),
    mustChangePassword: !!mustChange,
    isPasswordChanged: isPwChanged ? 'YES' : 'NO',
  });
});

// Authentication: Change Password Endpoint
app.post('/api/auth/change-password', (req, res) => {
  const { userId, newPassword } = req.body || {};
  if (!userId || !newPassword || typeof newPassword !== 'string' || newPassword.trim().length < 6) {
    return res.status(400).json({ success: false, error: 'Valid userId and new password (min 6 characters) are required.' });
  }

  const trimmed = newPassword.trim();
  if (trimmed.toLowerCase() === 'password123!' || trimmed.toLowerCase() === 'password123' || trimmed.toLowerCase() === 'password') {
    return res.status(400).json({ success: false, error: 'You cannot use the default "Password123!" as your password.' });
  }

  const userIdx = bridgeState.users.findIndex((u) => u.id === userId);
  if (userIdx === -1) {
    return res.status(404).json({ success: false, error: 'User account not found.' });
  }

  const newHash = hashPassword(trimmed);
  const existing = bridgeState.users[userIdx];
  const updatedUser = {
    ...existing,
    passwordHash: newHash,
    isPasswordChanged: 'YES' as const,
    mustChangePassword: false,
  };
  delete updatedUser.password; // Strip any plaintext password

  bridgeState.users[userIdx] = updatedUser;
  persistBridgeState();

  res.json({
    success: true,
    message: 'Password successfully updated and securely hashed.',
    user: sanitizeUser(updatedUser),
  });
});

// Tasks Configuration
app.get('/api/tasks', (req, res) => {
  res.json(bridgeState.tasks || DEFAULT_DESIGNATION_TASKS);
});

app.post('/api/tasks', (req, res) => {
  if (req.body && typeof req.body === 'object') {
    bridgeState.tasks = { ...bridgeState.tasks, ...req.body };
    persistBridgeState();
    return res.json({ success: true, tasks: bridgeState.tasks });
  }
  res.status(400).json({ error: 'Invalid tasks payload' });
});

// Permissions Configuration
app.get('/api/permissions', (req, res) => {
  res.json(bridgeState.permissions || DEFAULT_ROLE_PERMISSIONS);
});

app.post('/api/permissions', (req, res) => {
  if (req.body && typeof req.body === 'object') {
    bridgeState.permissions = { ...bridgeState.permissions, ...req.body };
    persistBridgeState();
    return res.json({ success: true, permissions: bridgeState.permissions });
  }
  res.status(400).json({ error: 'Invalid permissions payload' });
});

// Config Endpoints
app.get('/api/config', (req, res) => {
  res.json(bridgeState.config);
});

app.post('/api/config', (req, res) => {
  if (req.body && typeof req.body === 'object') {
    bridgeState.config = {
      ...bridgeState.config,
      ...req.body,
    };
    persistBridgeState();
  }
  res.json({ success: true, config: bridgeState.config });
});

// Presence Endpoints
app.get('/api/presence', (req, res) => {
  cleanStalePresence();
  res.json(Object.values(bridgeState.presence));
});

app.post('/api/presence', (req, res) => {
  const p = req.body;
  if (!p || !p.userId) {
    return res.status(400).json({ error: 'Missing userId in presence payload' });
  }

  const existing = bridgeState.presence[p.userId] || {};
  const sanitizedName = resolveStaffName(p.employeeCode || existing.employeeCode, p.userName || existing.userName, p.userName || existing.userName, p.userId);
  bridgeState.presence[p.userId] = {
    ...existing,
    ...p,
    userName: sanitizedName,
    lastHeartbeat: p.lastHeartbeat || new Date().toISOString(),
  };

  persistBridgeState();
  forwardToAppsScript('SYNC_PRESENCE', { presence: [bridgeState.presence[p.userId]] });
  res.json({ success: true, presence: bridgeState.presence[p.userId] });
});

app.post('/api/presence/batch', (req, res) => {
  const list = req.body;
  if (Array.isArray(list)) {
    for (const p of list) {
      if (p && p.userId) {
        const existing = bridgeState.presence[p.userId] || {};
        const sanitizedName = resolveStaffName(p.employeeCode || existing.employeeCode, p.userName || existing.userName, p.userName || existing.userName, p.userId);
        bridgeState.presence[p.userId] = {
          ...existing,
          ...p,
          userName: sanitizedName,
          lastHeartbeat: p.lastHeartbeat || new Date().toISOString(),
        };
      }
    }
    persistBridgeState();
  }
  res.json({ success: true, count: Object.keys(bridgeState.presence).length });
});

// TimeLogs Endpoints (Preserves individual historical sessions)
app.get('/api/timelogs', (req, res) => {
  res.json(bridgeState.timelogs);
});

app.post('/api/timelogs', (req, res) => {
  const incoming = req.body;
  if (Array.isArray(incoming)) {
    const map = new Map<string, any>(bridgeState.timelogs.map((l) => [l.id, l]));
    for (const rawLog of incoming) {
      if (rawLog && rawLog.id) {
        const existing = map.get(rawLog.id) || {};
        const durationSec = Math.max(0, Math.round(Number(rawLog.durationSeconds || existing.durationSeconds || 0)));
        map.set(rawLog.id, {
          ...existing,
          ...rawLog,
          durationSeconds: durationSec,
          sessionId: rawLog.sessionId || rawLog.id,
        });
      }
    }
    bridgeState.timelogs = Array.from(map.values());
    persistBridgeState();
    forwardToAppsScript('SYNC_TIMELOGS', { timeLogs: incoming });
    return res.json({ success: true, count: bridgeState.timelogs.length });
  } else if (incoming && incoming.id) {
    const map = new Map<string, any>(bridgeState.timelogs.map((l) => [l.id, l]));
    const existing = map.get(incoming.id) || {};
    const durationSec = Math.max(
      Math.round(Number(incoming.durationSeconds || 0)),
      Math.round(Number(existing.durationSeconds || 0)),
      0
    );

    const mergedLog = {
      ...existing,
      ...incoming,
      durationSeconds: durationSec,
      sessionId: incoming.sessionId || existing.sessionId || incoming.id,
    };

    if (existing.status === 'completed' && incoming.status !== 'completed') {
      mergedLog.status = existing.status;
      mergedLog.endTime = existing.endTime || mergedLog.endTime;
      mergedLog.geoLocalEndTime = existing.geoLocalEndTime || mergedLog.geoLocalEndTime;
    }

    map.set(incoming.id, mergedLog);
    bridgeState.timelogs = Array.from(map.values());
    persistBridgeState();
    forwardToAppsScript('SYNC_TIMELOGS', { timeLogs: [mergedLog] });
    return res.json({ success: true, log: mergedLog });
  }
  res.status(400).json({ error: 'Invalid timelog payload' });
});

// Users Endpoints (Never returns plaintext password or passwordHash)
app.get('/api/users', (req, res) => {
  const sanitized = bridgeState.users.map((u) => sanitizeUser(u));
  res.json(sanitized);
});

app.post('/api/users', (req, res) => {
  const incoming = req.body;
  if (Array.isArray(incoming)) {
    const map = new Map<string, any>(bridgeState.users.map((u) => [u.id, u]));
    for (const rawU of incoming) {
      if (rawU && rawU.id) {
        const existing = map.get(rawU.id) || {};
        const hasExistingRealHash = !!existing.passwordHash;
        const incomingPassword = String(rawU.password || '').trim();
        const isDefault = !incomingPassword || incomingPassword === 'Password123!';

        const merged = {
          ...existing,
          ...rawU,
          name: resolveStaffName(rawU.employeeCode, rawU.username, rawU.name, rawU.id),
          isPasswordChanged: hasExistingRealHash && existing.isPasswordChanged === 'YES' ? 'YES' : (rawU.isPasswordChanged || (isDefault ? 'NO' : 'YES')),
          mustChangePassword: hasExistingRealHash && existing.isPasswordChanged === 'YES' ? false : (rawU.mustChangePassword ?? isDefault),
          passwordHash: hasExistingRealHash
            ? existing.passwordHash
            : (!isDefault ? hashPassword(incomingPassword) : hashPassword('Password123!')),
        };
        delete merged.password;
        map.set(rawU.id, merged);
      }
    }
    bridgeState.users = Array.from(map.values());
    persistBridgeState();
    return res.json({ success: true, count: bridgeState.users.length });
  } else if (incoming && incoming.id) {
    const map = new Map<string, any>(bridgeState.users.map((u) => [u.id, u]));
    const existing = map.get(incoming.id) || {};
    const hasExistingRealHash = !!existing.passwordHash;
    const incomingPassword = String(incoming.password || '').trim();
    const isDefault = !incomingPassword || incomingPassword === 'Password123!';

    const merged = {
      ...existing,
      ...incoming,
      name: resolveStaffName(incoming.employeeCode, incoming.username, incoming.name, incoming.id),
      isPasswordChanged: hasExistingRealHash && existing.isPasswordChanged === 'YES' ? 'YES' : (incoming.isPasswordChanged || (isDefault ? 'NO' : 'YES')),
      mustChangePassword: hasExistingRealHash && existing.isPasswordChanged === 'YES' ? false : (incoming.mustChangePassword ?? isDefault),
      passwordHash: hasExistingRealHash
        ? existing.passwordHash
        : (!isDefault ? hashPassword(incomingPassword) : hashPassword('Password123!')),
    };
    delete merged.password;
    map.set(incoming.id, merged);
    bridgeState.users = Array.from(map.values());
    persistBridgeState();
    return res.json({ success: true, user: sanitizeUser(merged) });
  }
  res.status(400).json({ error: 'Invalid user payload' });
});

// Attendance Endpoints
app.get('/api/attendance', (req, res) => {
  res.json(bridgeState.attendance);
});

app.post('/api/attendance', (req, res) => {
  const incoming = req.body;
  if (Array.isArray(incoming)) {
    const map = new Map<string, any>(bridgeState.attendance.map((a) => [a.id || `${a.userId}_${a.date}`, a]));
    for (const a of incoming) {
      const k = a.id || `${a.userId}_${a.date}`;
      if (k) {
        map.set(k, { ...(map.get(k) || {}), ...a });
      }
    }
    bridgeState.attendance = Array.from(map.values());
    persistBridgeState();
    return res.json({ success: true, count: bridgeState.attendance.length });
  } else if (incoming) {
    const k = incoming.id || `${incoming.userId}_${incoming.date}`;
    const map = new Map<string, any>(bridgeState.attendance.map((a) => [a.id || `${a.userId}_${a.date}`, a]));
    map.set(k, { ...(map.get(k) || {}), ...incoming });
    bridgeState.attendance = Array.from(map.values());
    persistBridgeState();
    return res.json({ success: true, attendance: incoming });
  }
  res.status(400).json({ error: 'Invalid attendance payload' });
});

// AuditLogs Endpoints
app.get('/api/auditlogs', (req, res) => {
  res.json(bridgeState.auditlogs);
});

app.post('/api/auditlogs', (req, res) => {
  const incoming = req.body;
  if (incoming && incoming.id) {
    const exists = bridgeState.auditlogs.some((l) => l.id === incoming.id);
    if (!exists) {
      bridgeState.auditlogs = [incoming, ...bridgeState.auditlogs].slice(0, 1000);
      persistBridgeState();
    }
    return res.json({ success: true, log: incoming });
  }
  res.status(400).json({ error: 'Invalid auditlog payload' });
});

// Google Sheets Sync Proxy (Sandbox Only)
app.post('/api/sync-sheets', async (req, res) => {
  try {
    const webhookUrl = (req.body?.webhookUrl || bridgeState.config.webhookUrl || '').trim();
    if (isProhibitedProductionTarget(webhookUrl)) {
      return res.status(403).json({
        success: false,
        error: 'Prohibited production Google Sheets / Apps Script target detected. Sandbox cannot interact with production spreadsheet.',
      });
    }

    if (!webhookUrl || typeof webhookUrl !== 'string' || !webhookUrl.startsWith('https://')) {
      return res.status(400).json({
        success: false,
        error: 'Sandbox Google Apps Script webhook URL is not configured. Falling back to production is strictly forbidden.',
        missingSetup: 'SANDBOX_APPS_SCRIPT_URL',
      });
    }

    if (webhookUrl && webhookUrl !== bridgeState.config.webhookUrl) {
      bridgeState.config.webhookUrl = webhookUrl;
      persistBridgeState();
    }

    const payload = req.body?.payload || req.body;
    const fetchResponse = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      redirect: 'follow',
      signal: AbortSignal.timeout(6000),
    });

    const text = await fetchResponse.text();
    let googleResult: any;
    try {
      googleResult = JSON.parse(text);
    } catch {
      googleResult = { response: text };
    }

    const isSuccess =
      fetchResponse.ok &&
      (googleResult?.status === 'SUCCESS' ||
        googleResult?.success === true ||
        googleResult?.action === 'HEARTBEAT_UPDATE' ||
        googleResult?.action === payload?.action);

    return res.status(fetchResponse.ok ? 200 : fetchResponse.status).json({
      success: isSuccess,
      status: fetchResponse.status,
      appsScriptStatus:
        googleResult?.status ||
        (googleResult?.success ? 'SUCCESS' : 'UNKNOWN'),
      action: googleResult?.action || payload?.action,
      result: googleResult,
      error: !isSuccess
        ? googleResult?.message ||
          googleResult?.error ||
          (fetchResponse.ok
            ? 'Sandbox Apps Script returned non-success response'
            : `HTTP Error ${fetchResponse.status}`)
        : undefined,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || String(err) });
  }
});

app.get('/api/sync-sheets', async (req, res) => {
  try {
    const webhookUrl = ((req.query?.url as string) || bridgeState.config.webhookUrl || '').trim();
    if (isProhibitedProductionTarget(webhookUrl)) {
      return res.status(403).json({
        success: false,
        error: 'Prohibited production Google Sheets / Apps Script target detected. Sandbox cannot interact with production spreadsheet.',
      });
    }

    if (!webhookUrl || typeof webhookUrl !== 'string' || !webhookUrl.startsWith('https://')) {
      return res.status(400).json({
        success: false,
        error: 'Sandbox Google Apps Script webhook URL is not configured. Falling back to production is strictly forbidden.',
        missingSetup: 'SANDBOX_APPS_SCRIPT_URL',
      });
    }

    const fetchResponse = await fetch(webhookUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(6000),
    });

    const text = await fetchResponse.text();
    let jsonResult;
    try {
      jsonResult = JSON.parse(text);
    } catch {
      jsonResult = { response: text };
    }

    res.json(jsonResult);
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || String(err) });
  }
});

// Fallback for unmatched API routes: return JSON error, NEVER index.html
app.all('/api/*', (req, res) => {
  res.status(404).json({ error: `API route not found: ${req.method} ${req.url}` });
});

// ==========================================
// VITE / STATIC MIDDLEWARE
// ==========================================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        watch: {
          ignored: ['**/.sync_bridge.json'],
        },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`LLC Time Tracker Central Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
