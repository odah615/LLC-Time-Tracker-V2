// Cloudflare Pages Advanced Mode Worker for LLC Time Tracker Sandbox
// Stateless proxy between React UI / Desktop app and Google Apps Script.
// Google Sheets (via Apps Script) is the ONLY source of truth.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
};

const PROHIBITED_PRODUCTION_MARKERS = [
  "AKfycbyKGMOWV0u5xcv_lOKBk6LXpbjrlgZiuqtCs3_HbqjekoJZdXpdfA_1kDjP7H0ulLsw3Q",
  "1h8ssmDEcV-PMGlkpOzfQCtlRpnoT0CBQQveT3e4wPfA",
];

const ALLOWED_SYNC_ACTIONS = new Set([
  "AUTH_LOGIN",
  "UPDATE_PASSWORD",
  "ADMIN_RESET_PASSWORD",
  "GET_EMPLOYEES",
  "GET_TIMELOGS",
  "GET_PRESENCE",
  "GET_ATTENDANCE",
  "SYNC_TIMELOGS",
  "SYNC_USERS",
  "SYNC_PRESENCE",
  "SYNC_ATTENDANCE",
  "LOG_AUDIT",
]);

const FORBIDDEN_SYNC_ACTIONS = new Set([
  "GET_AUTH_EMPLOYEES",
  "GET_ALL",
  "READ_ALL",
  "SYNC_ALL",
]);

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
      ...extraHeaders,
    },
  });
}

function checkRequiredEnv(env) {
  const missing = [];
  const scriptUrl = env?.SANDBOX_APPS_SCRIPT_URL || env?.LIVE_APPS_SCRIPT_URL || env?.APPS_SCRIPT_URL;
  const scriptSecret = env?.SANDBOX_APPS_SCRIPT_SECRET || env?.LIVE_APPS_SCRIPT_SECRET || env?.APPS_SCRIPT_SECRET;
  const jwtSecret = env?.JWT_SECRET;

  if (!scriptUrl) missing.push("SANDBOX_APPS_SCRIPT_URL");
  if (!scriptSecret) missing.push("SANDBOX_APPS_SCRIPT_SECRET");
  if (!jwtSecret || typeof jwtSecret !== "string" || jwtSecret.trim() === "") missing.push("JWT_SECRET");

  if (missing.length > 0) {
    return jsonResponse(
      {
        error: `Server configuration error: Missing required environment variable(s): ${missing.join(", ")}`,
        missingVariables: missing,
        missingSetup: missing[0],
      },
      500
    );
  }
  return null;
}

function isProhibitedProductionTarget(target) {
  if (!target) return false;
  const str = String(target);
  return PROHIBITED_PRODUCTION_MARKERS.some((m) => str.includes(m));
}

/**
 * Forward request to Google Apps Script with 20s timeout and secret injection.
 * In callAppsScript, build body as { ...payload, action, secret: scriptSecret }
 * so caller can never override secret or action.
 */
async function callAppsScript(action, payload = {}, env, timeoutMs = 20000) {
  const envError = checkRequiredEnv(env);
  if (envError) {
    return {
      ok: false,
      status: 500,
      data: null,
      error: "Missing required environment variables",
    };
  }

  const targetUrl = (env?.SANDBOX_APPS_SCRIPT_URL || env?.LIVE_APPS_SCRIPT_URL || env?.APPS_SCRIPT_URL || "").trim();
  const scriptSecret = (env?.SANDBOX_APPS_SCRIPT_SECRET || env?.LIVE_APPS_SCRIPT_SECRET || env?.APPS_SCRIPT_SECRET || "").trim();

  if (isProhibitedProductionTarget(targetUrl)) {
    return {
      ok: false,
      status: 403,
      data: null,
      error: "Access to production Google Sheets or Apps Script endpoint is prohibited in sandbox mode.",
      isProhibited: true,
    };
  }

  if (!targetUrl.startsWith("https://script.google.com/macros/s/")) {
    return {
      ok: false,
      status: 400,
      data: null,
      error: "Invalid Google Apps Script URL format. URL must start with https://script.google.com/macros/s/",
    };
  }

  const outgoingBody = {
    ...payload,
    action,
    secret: scriptSecret,
  };

  try {
    const res = await fetch(targetUrl, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify(outgoingBody),
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
    });

    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    const isSuccess = res.ok && data && data.status === "SUCCESS";
    return {
      ok: isSuccess,
      status: res.ok ? 200 : res.status,
      data,
      error: !isSuccess
        ? data?.message || data?.error || `Apps Script error (status: ${data?.status || res.status})`
        : null,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      status: 504,
      data: null,
      error: `Apps Script request failed: ${message}`,
    };
  }
}

// ==========================================
// DEFAULT TASKS & ROLE PERMISSIONS (Ephemeral Memory)
// ==========================================
let cachedTasks = {
  "Outbound Agent/Team": [
    "Data Entry & Market Research",
    "Email Reachout",
    "Follow-up",
    "Training",
    "Team Meeting",
    "Coaching",
  ],
  "Inbound Agent/Team": [
    "Email Interaction",
    "Training",
    "Team Meeting",
    "Coaching",
  ],
  Agent: [
    "Data Entry & Market Research",
    "Email Reachout",
    "Email Interaction",
    "Follow-up",
    "Training",
    "Team Meeting",
    "Coaching",
  ],
  "Team Leader": [
    "Team Supervision",
    "Team Meeting",
    "Training",
    "Coaching",
    "QA Review",
    "On Shift",
  ],
  Trainer: [
    "Training",
    "Coaching",
    "Team Meeting",
    "QA Review",
    "On Shift",
  ],
  Admin: [
    "System Ops Review",
    "On Shift",
  ],
  "Super Admin": [
    "System Ops Review",
    "On Shift",
  ],
  "QA Specialist": [
    "QA Email Audit",
    "Other QA Reviews",
    "QA Coaching",
  ],
  Writer: [
    "Content Writing",
    "Team Meeting",
    "On Shift",
  ],
  HR: [
    "Team Meeting",
    "HR & Recruitment",
    "Payroll Task",
    "On Shift",
  ],
  "Payroll Officer": [
    "Payroll Task",
    "On Shift",
    "Team Meeting",
  ],
};

let cachedPermissions = {
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

// ==========================================
// JWT AUTHENTICATION HELPERS
// ==========================================

function getJwtSecret(env) {
  const secret = env?.JWT_SECRET;
  if (!secret || typeof secret !== "string" || secret.trim() === "") {
    throw new Error("Server configuration error: Missing JWT_SECRET environment variable.");
  }
  return secret;
}

async function createToken(payload, secret) {
  if (!secret || typeof secret !== "string") {
    throw new Error("Server configuration error: Missing JWT_SECRET environment variable.");
  }
  const enc = new TextEncoder();
  const header = { alg: "HS256", typ: "JWT" };
  const b64Header = btoa(JSON.stringify(header))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  const b64Payload = btoa(JSON.stringify(payload))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  const dataToSign = `${b64Header}.${b64Payload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(dataToSign));
  const b64Sig = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${dataToSign}.${b64Sig}`;
}

async function verifyToken(token, secret) {
  if (!secret || typeof secret !== "string") return null;
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [b64Header, b64Payload, b64Sig] = parts;
  const dataToSign = `${b64Header}.${b64Payload}`;
  const enc = new TextEncoder();

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigStr = atob(b64Sig.replace(/-/g, "+").replace(/_/g, "/"));
    const sigBytes = new Uint8Array(sigStr.length);
    for (let i = 0; i < sigStr.length; i++) sigBytes[i] = sigStr.charCodeAt(i);

    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      enc.encode(dataToSign)
    );
    if (!isValid) return null;

    const payloadJson = atob(b64Payload.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(payloadJson);
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

async function getAuthUser(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1];
  let secret;
  try {
    secret = getJwtSecret(env);
  } catch {
    return null;
  }
  return verifyToken(token, secret);
}

function sanitizeUser(user) {
  if (!user || typeof user !== "object") return null;
  const { password, accountPassword, passwordHash, ...safe } = user;
  return safe;
}

// ==========================================
// API ROUTE HANDLERS
// ==========================================

async function handleHealth(request, env) {
  let totalUsers = null;
  let appsScriptReachable = false;
  let appsScriptError = null;

  const res = await callAppsScript("GET_EMPLOYEES", {}, env, 5000);
  if (res.ok && res.data && Array.isArray(res.data.employees)) {
    appsScriptReachable = true;
    totalUsers = res.data.employees.length;
  } else {
    appsScriptReachable = false;
    appsScriptError = res.error || "Google Apps Script unreachable";
  }

  return jsonResponse({
    status: appsScriptReachable ? "ok" : "degraded",
    appsScriptReachable,
    appsScriptError,
    totalRegisteredUsers: totalUsers,
    runtime: "cloudflare-pages-worker",
    serverTime: new Date().toISOString(),
    onlineUsers: 0,
    trackingUsers: 0,
  });
}

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ success: false, error: "Invalid JSON payload" }, 400);
  }

  const { usernameOrCode, password } = body || {};
  if (!usernameOrCode || !password) {
    return jsonResponse(
      { success: false, error: "Username/Code and password are required" },
      400
    );
  }

  const result = await callAppsScript(
    "AUTH_LOGIN",
    {
      usernameOrCode: String(usernameOrCode).trim(),
      password: String(password),
    },
    env,
    20000
  );

  if (!result.ok || !result.data) {
    const errCode = result.data?.code || "";
    let msg = result.error || "Login failed.";
    if (errCode === "USER_NOT_FOUND") {
      msg = `Account not found for "${usernameOrCode}".`;
    } else if (errCode === "USER_INACTIVE") {
      msg = `Account for "${usernameOrCode}" is inactive.`;
    }
    return jsonResponse({ success: false, error: msg }, 401);
  }

  const user = result.data.user;
  if (!user || (!user.id && !user.username)) {
    return jsonResponse(
      { success: false, error: "Invalid user record retrieved from database." },
      500
    );
  }

  const mustChange = Boolean(result.data.mustChangePassword);

  let jwtSecret;
  try {
    jwtSecret = getJwtSecret(env);
  } catch (err) {
    return jsonResponse(
      { success: false, error: err.message },
      500
    );
  }

  const token = await createToken(
    {
      userId: user.id,
      username: user.username,
      employeeCode: user.employeeCode,
      role: user.role,
      designation: user.designation,
      exp: Math.floor(Date.now() / 1000) + 7 * 86400,
    },
    jwtSecret
  );

  return jsonResponse({
    success: true,
    token,
    user: sanitizeUser(user),
    mustChangePassword: mustChange,
  });
}

async function handleChangePassword(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) {
    return jsonResponse({ success: false, error: "Unauthorized: Missing or invalid authentication token." }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ success: false, error: "Invalid JSON payload" }, 400);
  }

  const { userId, newPassword, currentPassword } = body || {};

  if (!userId || !newPassword || typeof newPassword !== "string" || newPassword.trim().length < 6) {
    return jsonResponse(
      { success: false, error: "Valid userId and new password (min 6 characters) are required." },
      400
    );
  }

  const isOwner = authUser.userId === userId;
  const isAdmin = authUser.role === "admin";
  if (!isOwner && !isAdmin) {
    return jsonResponse({ success: false, error: "Forbidden: You can only change your own password." }, 403);
  }

  if (currentPassword) {
    const usernameForVerification = authUser.username || authUser.employeeCode || authUser.userId || userId;
    const authCheck = await callAppsScript(
      "AUTH_LOGIN",
      {
        usernameOrCode: String(usernameForVerification).trim(),
        password: String(currentPassword),
      },
      env,
      15000
    );

    if (!authCheck.ok || authCheck.data?.status !== "SUCCESS") {
      return jsonResponse(
        { success: false, verified: false, error: "Current password is incorrect." },
        400
      );
    }
  }

  const result = await callAppsScript(
    "UPDATE_PASSWORD",
    {
      userId: String(userId).trim(),
      employeeCode: authUser.employeeCode,
      username: authUser.username,
      newPassword: String(newPassword).trim(),
      currentPassword: currentPassword ? String(currentPassword) : undefined,
    },
    env,
    20000
  );

  if (result.ok && result.data && result.data.verified === true) {
    return jsonResponse({
      success: true,
      verified: true,
      message: "Password successfully updated in Google Sheets.",
      user: { id: userId, isPasswordChanged: "YES", mustChangePassword: false },
      mustChangePassword: false,
      isPasswordChanged: "YES",
    });
  }

  return jsonResponse(
    {
      success: false,
      verified: false,
      error: result.data?.message || result.error || "Password change could not be verified by Google Sheets.",
    },
    400
  );
}

async function handleUsersGet(request, env) {
  const url = new URL(request.url);
  const userId = url.searchParams.get("userId") || undefined;

  const result = await callAppsScript("GET_EMPLOYEES", { userId }, env, 20000);
  if (!result.ok || !result.data || !Array.isArray(result.data.employees)) {
    return jsonResponse(
      { success: false, error: result.error || "Failed to fetch users from Google Sheets." },
      502
    );
  }

  const sanitized = result.data.employees.map((e) => sanitizeUser(e));
  return jsonResponse(sanitized);
}

async function handleUsersPost(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) {
    return jsonResponse({ success: false, error: "Unauthorized: Missing or invalid token." }, 401);
  }

  const allowedRoles = ["admin", "trainer", "hr"];
  const canEdit = allowedRoles.includes(authUser.role) || authUser.canEditEmployees === true;

  if (!canEdit) {
    return jsonResponse(
      { success: false, error: "Forbidden: You do not have permission to manage employees." },
      403
    );
  }

  let incoming;
  try {
    incoming = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  if (incoming && incoming.action === "ADMIN_RESET_PASSWORD") {
    if (authUser.role !== "admin") {
      return jsonResponse({ success: false, error: "Forbidden: Only administrators can reset passwords." }, 403);
    }

    const { userId, temporaryPassword } = incoming;
    if (!userId || !temporaryPassword) {
      return jsonResponse(
        { success: false, error: "Both userId and temporaryPassword are required for ADMIN_RESET_PASSWORD." },
        400
      );
    }

    const result = await callAppsScript(
      "ADMIN_RESET_PASSWORD",
      { userId, temporaryPassword },
      env,
      20000
    );

    if (!result.ok || result.data?.status !== "SUCCESS") {
      return jsonResponse({ success: false, error: result.error || "Password reset failed" }, 500);
    }
    return jsonResponse({ success: true, message: "Password reset successfully in Google Sheets." });
  }

  const isEditing = Boolean(incoming?.id);
  const cleanProfile = { ...incoming };
  
  delete cleanProfile.password;
  delete cleanProfile.accountPassword;
  delete cleanProfile.passwordHash;
  if (isEditing) {
    delete cleanProfile.mustChangePassword;
    delete cleanProfile.isPasswordChanged;
  }

  const result = await callAppsScript(
    "SYNC_USERS",
    { users: [cleanProfile] },
    env,
    20000
  );

  if (!result.ok || result.data?.status !== "SUCCESS") {
    return jsonResponse(
      { success: false, error: result.error || "Failed to update employee in Google Sheets." },
      502
    );
  }

  return jsonResponse({
    success: true,
    user: sanitizeUser(result.data?.user || cleanProfile),
  });
}

async function handleTasksGet() {
  return jsonResponse(cachedTasks);
}

async function handleTasksPost(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  if (body && typeof body === "object") {
    cachedTasks = { ...cachedTasks, ...body };
    return jsonResponse({ success: true, tasks: cachedTasks });
  }
  return jsonResponse({ error: "Invalid tasks payload" }, 400);
}

async function handlePermissionsGet() {
  return jsonResponse(cachedPermissions);
}

async function handlePermissionsPost(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  if (body && typeof body === "object") {
    cachedPermissions = { ...cachedPermissions, ...body };
    return jsonResponse({ success: true, permissions: cachedPermissions });
  }
  return jsonResponse({ error: "Invalid permissions payload" }, 400);
}

async function handleTimelogsGet(request, env) {
  const url = new URL(request.url);
  const userId = url.searchParams.get("userId") || undefined;
  const days = url.searchParams.get("days") ? parseInt(url.searchParams.get("days"), 10) : 45;
  const since = url.searchParams.get("since") || undefined;

  const result = await callAppsScript(
    "GET_TIMELOGS",
    { userId, days, since },
    env,
    20000
  );

  if (!result.ok || !result.data) {
    return jsonResponse([]);
  }

  return jsonResponse(result.data.timelogs || result.data.timeLogs || []);
}

async function handleTimelogsPost(request, env) {
  let incoming;
  try {
    incoming = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  if (!incoming) {
    return jsonResponse({ error: "Invalid timelog payload" }, 400);
  }

  const rawLogs = Array.isArray(incoming) ? incoming : [incoming];
  if (rawLogs.length === 0) {
    return jsonResponse({ error: "Empty timelog payload" }, 400);
  }

  const timeLogs = rawLogs.map((log) => ({
    ...log,
    sessionId: log.sessionId || log.id,
    durationSeconds: Math.round(Number(log.durationSeconds || 0)),
  }));

  const result = await callAppsScript(
    "SYNC_TIMELOGS",
    { timeLogs },
    env,
    20000
  );

  if (!result.ok || result.data?.status !== "SUCCESS") {
    return jsonResponse(
      { success: false, error: result.error || "Failed to save timelog to Google Sheets." },
      502
    );
  }

  return jsonResponse({ success: true, log: timeLogs[0], timeLogs });
}

async function handlePresenceGet(request, env) {
  const result = await callAppsScript("GET_PRESENCE", {}, env, 20000);
  if (!result.ok || !result.data) {
    return jsonResponse([]);
  }
  return jsonResponse(result.data.presence || result.data.presenceList || []);
}

async function handlePresencePost(request, env) {
  let incoming;
  try {
    incoming = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  if (!incoming) {
    return jsonResponse({ error: "Missing presence payload" }, 400);
  }

  const presenceList = Array.isArray(incoming) ? incoming : [incoming];

  const result = await callAppsScript(
    "SYNC_PRESENCE",
    { presence: presenceList },
    env,
    20000
  );

  if (!result.ok || result.data?.status !== "SUCCESS") {
    return jsonResponse({ success: false, error: result.error }, 500);
  }
  return jsonResponse({ success: true, presence: presenceList[0], presenceList });
}

async function handleAttendanceGet(request, env) {
  const result = await callAppsScript("GET_ATTENDANCE", {}, env, 20000);
  if (!result.ok || !result.data) {
    return jsonResponse([]);
  }
  return jsonResponse(result.data.attendance || []);
}

async function handleAttendancePost(request, env) {
  let incoming;
  try {
    incoming = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  if (!incoming) {
    return jsonResponse({ error: "Missing attendance payload" }, 400);
  }

  const attendance = Array.isArray(incoming) ? incoming : [incoming];

  const result = await callAppsScript(
    "SYNC_ATTENDANCE",
    { attendance },
    env,
    20000
  );

  if (!result.ok || result.data?.status !== "SUCCESS") {
    return jsonResponse({ success: false, error: result.error || "Failed to sync attendance." }, 500);
  }
  return jsonResponse({ success: true, attendance });
}

async function handleAuditlogsGet() {
  return jsonResponse([]);
}

async function handleAuditlogsPost(request, env) {
  let incoming;
  try {
    incoming = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  if (!incoming) {
    return jsonResponse({ error: "Missing audit payload" }, 400);
  }

  const logs = Array.isArray(incoming) ? incoming : [incoming];

  const result = await callAppsScript(
    "LOG_AUDIT",
    { logs },
    env,
    20000
  );

  if (!result.ok || result.data?.status !== "SUCCESS") {
    return jsonResponse({ success: false, error: result.error || "Failed to log audit event." }, 500);
  }
  return jsonResponse({ success: true, logs });
}

async function handleSyncSheetsPost(request, env) {
  const authUser = await getAuthUser(request, env);
  if (!authUser) {
    return jsonResponse({ success: false, error: "Unauthorized: Missing or invalid token." }, 401);
  }

  let body = {};
  try {
    body = await request.json();
  } catch {}

  const payload = body?.payload || body;
  const action = payload?.action || body?.action;

  if (!action) {
    return jsonResponse({ success: false, error: "Action is required in payload." }, 400);
  }

  if (FORBIDDEN_SYNC_ACTIONS.has(action)) {
    return jsonResponse(
      { success: false, error: `Forbidden action: '${action}' exposes sensitive credential data.` },
      403
    );
  }

  if (!ALLOWED_SYNC_ACTIONS.has(action)) {
    return jsonResponse(
      { success: false, error: `Action '${action}' is not permitted on this proxy route.` },
      403
    );
  }

  const result = await callAppsScript(action, payload, env, 20000);
  return jsonResponse(
    {
      success: result.ok,
      status: result.status,
      result: result.data,
      error: result.error,
    },
    result.ok ? 200 : result.status
  );
}

// ==========================================
// WORKER DEFAULT EXPORT (Pages Advanced Mode)
// ==========================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Global OPTIONS preflight for all /api/ routes
    if (request.method === "OPTIONS" && url.pathname.startsWith("/api/")) {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    // Environmental secret check for all /api/ endpoints
    if (url.pathname.startsWith("/api/")) {
      const envError = checkRequiredEnv(env);
      if (envError) return envError;
    }

    // Health Endpoint
    if (url.pathname === "/api/health" && (request.method === "GET" || request.method === "HEAD")) {
      if (request.method === "HEAD") {
        return new Response(null, {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }
      return handleHealth(request, env);
    }

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      return handleLogin(request, env);
    }

    if (url.pathname === "/api/auth/change-password" && request.method === "POST") {
      return handleChangePassword(request, env);
    }

    if (url.pathname === "/api/users") {
      if (request.method === "GET") return handleUsersGet(request, env);
      if (request.method === "POST") return handleUsersPost(request, env);
    }

    if (url.pathname === "/api/attendance") {
      if (request.method === "GET") return handleAttendanceGet(request, env);
      if (request.method === "POST") return handleAttendancePost(request, env);
    }

    if (url.pathname === "/api/auditlogs") {
      if (request.method === "GET") return handleAuditlogsGet();
      if (request.method === "POST") return handleAuditlogsPost(request, env);
    }

    if (url.pathname === "/api/tasks") {
      if (request.method === "GET") return handleTasksGet();
      if (request.method === "POST") return handleTasksPost(request);
    }

    if (url.pathname === "/api/permissions") {
      if (request.method === "GET") return handlePermissionsGet();
      if (request.method === "POST") return handlePermissionsPost(request);
    }

    if (url.pathname === "/api/timelogs" || url.pathname === "/api/timesheets") {
      if (request.method === "GET") return handleTimelogsGet(request, env);
      if (request.method === "POST") return handleTimelogsPost(request, env);
    }

    if (url.pathname === "/api/presence" || url.pathname === "/api/presence/batch") {
      if (request.method === "GET") return handlePresenceGet(request, env);
      if (request.method === "POST") return handlePresencePost(request, env);
    }

    if (url.pathname === "/api/sync-sheets") {
      if (request.method === "POST") return handleSyncSheetsPost(request, env);
    }

    // Unknown /api/* routes return JSON 404
    if (url.pathname.startsWith("/api/")) {
      return jsonResponse(
        {
          error: `API route not found: ${request.method} ${url.pathname}`,
          status: 404,
        },
        404
      );
    }

    // Static Assets & Single Page Application (SPA) Fallback
    if (env?.ASSETS) {
      const assetResponse = await env.ASSETS.fetch(request);
      if (assetResponse.status === 404 && request.method === "GET") {
        const indexRequest = new Request(
          new URL("/index.html", request.url),
          request
        );
        return env.ASSETS.fetch(indexRequest);
      }
      return assetResponse;
    }

    return new Response("Not Found", { status: 404 });
  },
};
