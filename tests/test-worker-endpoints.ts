// Focused Test Suite for Cloudflare Pages Worker and Pages Functions (functions/api/[[catchall]].js)
// Tests all Phase 1 backend endpoints using synthetic data only.

import worker from '../src/server/apiHandler.js';
import { onRequest as pagesApiHandler } from '../functions/api/[[path]].js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (condition) {
    console.log(`  ✅ PASS: ${msg}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${msg}`);
    failed++;
  }
}

async function runTests() {
  console.log('🧪 Starting Cloudflare Pages Worker (_worker.js) Test Suite...\n');

  const mockAppsScriptUrl = 'https://script.google.com/macros/s/AKfycbx_mock_sandbox_app_script_id_123456789/exec';
  const mockSecret = 'test-secret-key-321';

  const mockDb = {
    users: [
      {
        id: 'usr-superadmin-red',
        employeeCode: 'SuperAdmin',
        username: 'admin',
        name: 'Admin',
        role: 'admin',
        designation: 'Admin',
        status: 'active',
        accountPassword: 'AdminpassW0rd123!',
        mustChangePassword: false,
      },
      {
        id: 'usr-llc-0003',
        employeeCode: 'LLC-0003',
        username: 'trainer',
        name: 'Pia',
        role: 'trainer',
        designation: 'Trainer',
        status: 'active',
        accountPassword: 'Password123!',
        mustChangePassword: true,
      },
      {
        id: 'usr-llc-0023',
        employeeCode: 'LLC-0023',
        username: 'jdavid',
        name: 'Juan David',
        role: 'agent',
        designation: 'Agent',
        status: 'active',
        accountPassword: 'Password123!',
        mustChangePassword: true,
      },
    ],
  };

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const urlStr = url.toString();
    if (urlStr.includes('script.google.com')) {
      let body: any = {};
      if (init?.body) {
        try {
          body = JSON.parse(init.body as string);
        } catch {}
      }

      if (body.action === 'AUTH_LOGIN') {
        const query = String(body.usernameOrCode || '').toLowerCase().trim();
        const pw = String(body.password || '');
        const found = mockDb.users.find(
          (u) =>
            u.username.toLowerCase() === query ||
            u.employeeCode.toLowerCase() === query ||
            u.id.toLowerCase() === query
        );

        if (!found) {
          return new Response(JSON.stringify({ status: 'ERROR', code: 'USER_NOT_FOUND', message: 'User not found' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (found.status === 'inactive') {
          return new Response(JSON.stringify({ status: 'ERROR', code: 'USER_INACTIVE', message: 'User inactive' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (found.accountPassword !== pw) {
          return new Response(JSON.stringify({ status: 'ERROR', code: 'INVALID_CREDENTIALS', message: 'Incorrect password' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        const { accountPassword, ...safe } = found;
        return new Response(
          JSON.stringify({
            status: 'SUCCESS',
            valid: true,
            mustChangePassword: found.mustChangePassword,
            user: safe,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'UPDATE_PASSWORD') {
        const target = mockDb.users.find((u) => u.id === body.userId);
        if (!target) {
          return new Response(JSON.stringify({ status: 'ERROR', code: 'USER_NOT_FOUND' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        target.accountPassword = body.newPassword;
        target.mustChangePassword = false;
        return new Response(
          JSON.stringify({ status: 'SUCCESS', action: 'UPDATE_PASSWORD', verified: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'GET_EMPLOYEES' || body.action === 'GET_ALL') {
        const safeList = mockDb.users.map(({ accountPassword, ...rest }) => rest);
        return new Response(
          JSON.stringify({ status: 'SUCCESS', employees: safeList }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'UPDATE_PRESENCE' || body.action === 'SYNC_PRESENCE') {
        if (!(mockDb as any).presence) (mockDb as any).presence = [];
        const items = Array.isArray(body.presence) ? body.presence : [body.presence];
        items.forEach((item: any) => {
          if (item) {
            (mockDb as any).presence = (mockDb as any).presence.filter((p: any) => p.userId !== item.userId);
            (mockDb as any).presence.push(item);
          }
        });
        return new Response(
          JSON.stringify({ status: 'SUCCESS', presence: items }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'GET_PRESENCE') {
        return new Response(
          JSON.stringify({ status: 'SUCCESS', presence: (mockDb as any).presence || [] }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'SYNC_TIMELOG' || body.action === 'SYNC_TIMELOGS') {
        if (!(mockDb as any).timelogs) (mockDb as any).timelogs = [];
        const logs = body.timeLogs || (body.timelog ? [body.timelog] : []);
        logs.forEach((log: any) => {
          if (log) {
            (mockDb as any).timelogs = (mockDb as any).timelogs.filter((l: any) => l.id !== log.id && l.sessionId !== log.sessionId);
            (mockDb as any).timelogs.push(log);
          }
        });
        return new Response(
          JSON.stringify({ status: 'SUCCESS', log: logs[0], timeLogs: logs }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'GET_TIMELOGS') {
        return new Response(
          JSON.stringify({ status: 'SUCCESS', timelogs: (mockDb as any).timelogs || [] }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'SYNC_EMPLOYEES' || body.action === 'SYNC_USERS') {
        return new Response(
          JSON.stringify({ status: 'SUCCESS', count: 1 }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ status: 'SUCCESS' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return originalFetch(url, init);
  }) as any;

  const mockEnv = {
    JWT_SECRET: 'test-secret-key-321',
    SANDBOX_APPS_SCRIPT_URL: mockAppsScriptUrl,
    SANDBOX_APPS_SCRIPT_SECRET: mockSecret,
    ASSETS: {
      fetch: async (req: Request) => {
        return new Response('<html>Mock Frontend</html>', {
          status: 200,
          headers: { 'Content-Type': 'text/html' },
        });
      },
    },
  };

  // 1. Health Check (via Worker and Pages Functions)
  console.log('1. Testing GET & HEAD /api/health:');
  const healthReq = new Request('http://localhost/api/health', { method: 'GET' });
  const healthRes = await worker.fetch(healthReq, mockEnv, {});
  const healthData = await healthRes.json();
  assert(healthRes.status === 200, 'Health endpoint returns HTTP 200');
  assert(healthData.status === 'ok', 'Health status is ok');
  assert(healthData.runtime === 'cloudflare-pages-worker', 'Runtime identifies as cloudflare-pages-worker');
  assert(typeof healthData.onlineUsers === 'number', 'Reports onlineUsers metric');

  // Verify HEAD /api/health returns HTTP 200 without payload body
  const healthHeadReq = new Request('http://localhost/api/health', { method: 'HEAD' });
  const healthHeadRes = await worker.fetch(healthHeadReq, mockEnv, {});
  assert(healthHeadRes.status === 200, 'HEAD /api/health returns HTTP 200');
  assert(healthHeadRes.headers.get('Content-Type')?.includes('application/json') || false, 'HEAD /api/health returns JSON headers');

  // Verify Pages Functions catch-all handler executes /api/health directly and returns JSON (never index.html)
  const pagesHealthReq = new Request('https://llc-time-tracker-sandbox.pages.dev/api/health', { method: 'GET' });
  const pagesHealthRes = await pagesApiHandler({
    request: pagesHealthReq,
    env: mockEnv,
    waitUntil: () => {},
    next: async () => new Response('<html>Mock Frontend HTML Fallback</html>', { status: 200 }),
  });
  assert(pagesHealthRes.status === 200, 'Pages Function onRequest handles /api/health with HTTP 200');
  const pagesContentType = pagesHealthRes.headers.get('Content-Type') || '';
  assert(pagesContentType.includes('application/json'), 'Pages Function returns application/json Content-Type, never text/html');
  const pagesHealthData = await pagesHealthRes.json();
  assert(pagesHealthData.status === 'ok', 'Pages Function returns valid health JSON payload');
  assert(typeof pagesHealthData.totalRegisteredUsers === 'number', 'Pages Function returns registered user count metric');

  // 2. Authentication Login (Valid & Invalid)
  console.log('\n2. Testing POST /api/auth/login:');
  const invalidLoginReq = new Request('http://localhost/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernameOrCode: 'admin', password: 'WrongPassword999!' }),
  });
  const invalidRes = await worker.fetch(invalidLoginReq, mockEnv, {});
  assert(invalidRes.status === 401, 'Invalid password returns HTTP 401');

  const validLoginReq = new Request('http://localhost/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernameOrCode: 'admin', password: 'AdminpassW0rd123!' }),
  });
  const validRes = await worker.fetch(validLoginReq, mockEnv, {});
  const validData = await validRes.json();
  assert(validRes.status === 200, 'Valid login returns HTTP 200');
  assert(validData.success === true, 'Login response success is true');
  assert(typeof validData.token === 'string', 'Returns JWT authentication token');
  assert(validData.user && !validData.user.password && !validData.user.passwordHash, 'User object is sanitized (no plaintext or hash exposed)');
  const adminToken = validData.token;

  // 3. Password Change
  console.log('\n3. Testing POST /api/auth/change-password:');
  const changePwReq = new Request('http://localhost/api/auth/change-password', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify({
      userId: 'usr-superadmin-red',
      currentPassword: 'AdminpassW0rd123!',
      newPassword: 'UpdatedAdminPass2026!',
    }),
  });
  const changeRes = await worker.fetch(changePwReq, mockEnv, {});
  const changeData = await changeRes.json();
  assert(changeRes.status === 200, 'Change password returns HTTP 200');
  assert(changeData.success === true, 'Password successfully changed');
  assert(changeData.user && changeData.user.isPasswordChanged === 'YES', 'isPasswordChanged updated to YES');

  // Verify login with new password
  const newLoginReq = new Request('http://localhost/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernameOrCode: 'admin', password: 'UpdatedAdminPass2026!' }),
  });
  const newLoginRes = await worker.fetch(newLoginReq, mockEnv, {});
  assert(newLoginRes.status === 200, 'Login with new updated password succeeds');

  // 4. Users Access & RBAC
  console.log('\n4. Testing GET & POST /api/users:');
  const usersGetReq = new Request('http://localhost/api/users', {
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const usersRes = await worker.fetch(usersGetReq, mockEnv, {});
  const usersData = await usersRes.json();
  assert(usersRes.status === 200, 'GET /api/users returns HTTP 200');
  assert(Array.isArray(usersData) && usersData.length > 0, 'Returns array of users');
  assert(!usersData.some((u: any) => u.password || u.passwordHash), 'All returned users are properly sanitized');

  // Create synthetic employee
  const createEmpReq = new Request('http://localhost/api/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify({
      id: 'usr-synth-999',
      employeeCode: 'LLC-9999',
      name: 'Synthetic Test Employee',
      username: 'synth_test',
      role: 'agent',
      designation: 'Outbound Agent/Team',
      password: 'InitialPassword123!',
    }),
  });
  const createRes = await worker.fetch(createEmpReq, mockEnv, {});
  const createData = await createRes.json();
  assert(createRes.status === 200, 'POST /api/users creates employee');
  assert(createData.user && createData.user.username === 'synth_test', 'Synthetic employee created with sanitized data');

  // 5. Tasks Management
  console.log('\n5. Testing GET & POST /api/tasks:');
  const tasksGetReq = new Request('http://localhost/api/tasks', { method: 'GET' });
  const tasksRes = await worker.fetch(tasksGetReq, mockEnv, {});
  const tasksData = await tasksRes.json();
  assert(tasksRes.status === 200, 'GET /api/tasks returns HTTP 200');
  assert(Array.isArray(tasksData['Outbound Agent/Team']), 'Tasks include Outbound Agent/Team designation tasks');

  // 6. Permissions Management
  console.log('\n6. Testing GET & POST /api/permissions:');
  const permsGetReq = new Request('http://localhost/api/permissions', { method: 'GET' });
  const permsRes = await worker.fetch(permsGetReq, mockEnv, {});
  const permsData = await permsRes.json();
  assert(permsRes.status === 200, 'GET /api/permissions returns HTTP 200');
  assert(permsData.admin && permsData.admin.canEditEmployees === true, 'Admin role permissions present');

  // 7. Presence Tracking (Ephemeral Live Presence)
  console.log('\n7. Testing POST & GET /api/presence:');
  const presencePostReq = new Request('http://localhost/api/presence', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId: 'usr-synth-999',
      employeeCode: 'LLC-9999',
      userName: 'Synthetic Test Employee',
      isOnline: true,
      status: 'active',
      isTracking: true,
      currentTask: 'Data Entry & Market Research',
      lastHeartbeat: new Date().toISOString(),
    }),
  });
  const presencePostRes = await worker.fetch(presencePostReq, mockEnv, {});
  assert(presencePostRes.status === 200, 'POST /api/presence returns HTTP 200');

  const presenceGetReq = new Request('http://localhost/api/presence', { method: 'GET' });
  const presenceGetRes = await worker.fetch(presenceGetReq, mockEnv, {});
  const presenceData = await presenceGetRes.json();
  assert(Array.isArray(presenceData) && presenceData.some((p: any) => p.userId === 'usr-synth-999'), 'GET /api/presence contains updated presence');

  // 8. Timelogs Management
  console.log('\n8. Testing POST & GET /api/timelogs:');
  const timelogPostReq = new Request('http://localhost/api/timelogs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: 'log-synth-001',
      sessionId: 'sess-synth-001',
      userId: 'usr-synth-999',
      task: 'Data Entry & Market Research',
      durationSeconds: 1800,
      status: 'completed',
    }),
  });
  const timelogPostRes = await worker.fetch(timelogPostReq, mockEnv, {});
  assert(timelogPostRes.status === 200, 'POST /api/timelogs returns HTTP 200');

  const timelogGetReq = new Request('http://localhost/api/timelogs', {
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const timelogGetRes = await worker.fetch(timelogGetReq, mockEnv, {});
  const timelogData = await timelogGetRes.json();
  assert(Array.isArray(timelogData) && timelogData.some((l: any) => l.id === 'log-synth-001'), 'GET /api/timelogs returns recorded timelog');

  // 9. Prohibited Production Webhook Guard
  console.log('\n9. Testing Security Guards for Production Webhook Protection:');
  const envWithProhibitedUrl = {
    ...mockEnv,
    SANDBOX_APPS_SCRIPT_URL: 'https://script.google.com/macros/s/AKfycbyKGMOWV0u5xcv_lOKBk6LXpbjrlgZiuqtCs3_HbqjekoJZdXpdfA_1kDjP7H0ulLsw3Q/exec',
  };
  const prohReq = new Request('http://localhost/api/sync-sheets', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify({
      payload: { action: 'SYNC_PRESENCE' },
    }),
  });
  const prohRes = await worker.fetch(prohReq, envWithProhibitedUrl, {});
  assert(prohRes.status === 403, 'Prohibited production webhook URL returns HTTP 403 Forbidden');

  // 10. Fail-Closed on Missing Sandbox Webhook
  console.log('\n10. Testing Fail-Closed on Missing Sandbox Webhook:');
  const envWithoutWebhook = {
    ...mockEnv,
    SANDBOX_APPS_SCRIPT_URL: '',
  };
  const missingHookReq = new Request('http://localhost/api/sync-sheets', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify({
      webhookUrl: '',
      payload: { action: 'SYNC_PRESENCE' },
    }),
  });
  const missingHookRes = await worker.fetch(missingHookReq, envWithoutWebhook, {});
  const missingHookData = await missingHookRes.json();
  assert(missingHookRes.status === 500 || missingHookRes.status === 400, 'Missing sandbox webhook returns HTTP 500/400 error');
  assert(missingHookData.missingSetup === 'SANDBOX_APPS_SCRIPT_URL', 'Identifies missing setup as SANDBOX_APPS_SCRIPT_URL');

  // 11. Fail Explicitly on Missing JWT_SECRET
  console.log('\n11. Testing Fail Explicitly on Missing JWT_SECRET:');
  const envWithoutJwtSecret = {
    ...mockEnv,
    JWT_SECRET: '',
  };
  const missingJwtReq = new Request('http://localhost/api/users', {
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const missingJwtRes = await worker.fetch(missingJwtReq, envWithoutJwtSecret, {});
  const missingJwtData = await missingJwtRes.json();
  assert(missingJwtRes.status === 500, 'Missing JWT_SECRET returns HTTP 500 server configuration error');
  assert(missingJwtData.missingSetup === 'JWT_SECRET', 'Identifies missing setup specifically as JWT_SECRET');

  // 12. API Route 404 Fallback (JSON, never HTML)
  console.log('\n12. Testing Unknown /api/* Route Safety:');
  const unknownApiReq = new Request('http://localhost/api/non-existent-endpoint', { method: 'GET' });
  const unknownApiRes = await worker.fetch(unknownApiReq, mockEnv, {});
  const unknownData = await unknownApiRes.json();
  assert(unknownApiRes.status === 404, 'Unknown API route returns HTTP 404');
  assert(typeof unknownData.error === 'string', 'Returns JSON error message, never falls through to HTML');

  // 13. Non-API Static Asset Delegation
  console.log('\n13. Testing Static Asset Delegation:');
  const staticReq = new Request('http://localhost/', { method: 'GET' });
  const staticRes = await worker.fetch(staticReq, mockEnv, {});
  assert(staticRes.status === 200, 'Non-API request delegates to env.ASSETS');

  console.log(`\n========================================`);
  console.log(`Test Results: ${passed} passed, ${failed} failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Test run failed with unhandled exception:', err);
  process.exit(1);
});
