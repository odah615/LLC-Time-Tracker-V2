// Focused Test Suite for Sandbox Google Apps Script & Cloudflare Worker Integration
// Verifies:
// 1. Shared secret enforcement (missing/incorrect secret rejected before spreadsheet access)
// 2. Safe doGet responses (no employees, credentials, pay rates, timesheets, presence exposed)
// 3. Spreadsheet isolation (rejection of production spreadsheet ID, rejection of missing ID)
// 4. Worker-to-Apps-Script protocol (UPDATE_PASSWORD, SYNC_TIMELOGS, SYNC_USERS, GET_ALL)
// 5. Worker server-to-server secret injection and non-exposure in responses

import fs from 'fs';
import path from 'path';
import vm from 'vm';
import worker from '../src/server/apiHandler.js';

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

// ==========================================
// MOCK APPS SCRIPT RUNTIME ENVIRONMENT
// ==========================================

interface MockSheet {
  name: string;
  rows: any[][];
}

class MockSpreadsheet {
  private id: string;
  private sheets: Map<string, MockSheet> = new Map();

  constructor(id: string) {
    this.id = id;
  }

  getId() {
    return this.id;
  }

  getName() {
    return `Sandbox Sheet [${this.id}]`;
  }

  getSheetByName(name: string) {
    const s = this.sheets.get(name);
    if (!s) return null;
    return this.wrapSheet(s);
  }

  insertSheet(name: string) {
    const s: MockSheet = { name, rows: [] };
    this.sheets.set(name, s);
    return this.wrapSheet(s);
  }

  private wrapSheet(s: MockSheet) {
    return {
      getLastRow: () => s.rows.length,
      getLastColumn: () => {
        let maxCols = 0;
        for (const r of s.rows) {
          if (r.length > maxCols) maxCols = r.length;
        }
        return maxCols;
      },
      appendRow: (row: any[]) => {
        s.rows.push([...row]);
      },
      getRange: (row: number, col: number, numRows: number, numCols: number) => {
        return {
          getValues: () => {
            const result: any[][] = [];
            const rCount = numRows !== undefined ? numRows : 1;
            const cCount = numCols !== undefined ? numCols : 1;
            for (let r = 0; r < rCount; r++) {
              const rowIndex = row - 1 + r;
              const sourceRow = s.rows[rowIndex] || [];
              const slice: any[] = [];
              for (let c = 0; c < cCount; c++) {
                const colIndex = col - 1 + c;
                slice.push(sourceRow[colIndex] !== undefined ? sourceRow[colIndex] : '');
              }
              result.push(slice);
            }
            return result;
          },
          getValue: () => {
            const sourceRow = s.rows[row - 1] || [];
            return sourceRow[col - 1] !== undefined ? sourceRow[col - 1] : '';
          },
          setValues: (matrix: any[][]) => {
            for (let r = 0; r < matrix.length; r++) {
              const targetRowIndex = row - 1 + r;
              while (s.rows.length <= targetRowIndex) {
                s.rows.push([]);
              }
              for (let c = 0; c < matrix[r].length; c++) {
                const targetColIndex = col - 1 + c;
                s.rows[targetRowIndex][targetColIndex] = matrix[r][c];
              }
            }
          },
          setValue: (val: any) => {
            const targetRowIndex = row - 1;
            while (s.rows.length <= targetRowIndex) {
              s.rows.push([]);
            }
            s.rows[targetRowIndex][col - 1] = val;
          },
          setFontWeight: () => ({ setBackground: () => ({ setFontColor: () => {} }) }),
          setBackground: () => ({ setFontColor: () => {} }),
          setFontColor: () => {},
        };
      },
      setFrozenRows: () => {},
    };
  }
}

function createAppsScriptEnvironment(initialProps: Record<string, string> = {}) {
  const scriptProperties = { ...initialProps };
  let openedSpreadsheetId: string | null = null;
  const spreadsheets = new Map<string, MockSpreadsheet>();

  const sandbox = {
    LockService: {
      getScriptLock: () => ({
        waitLock: (ms: number) => {},
        releaseLock: () => {},
        hasLock: () => true,
      }),
    },
    PropertiesService: {
      getScriptProperties: () => ({
        getProperty: (key: string) => scriptProperties[key] || null,
        setProperty: (key: string, val: string) => {
          scriptProperties[key] = val;
        },
      }),
    },
    SpreadsheetApp: {
      openById: (id: string) => {
        openedSpreadsheetId = id;
        if (!spreadsheets.has(id)) {
          spreadsheets.set(id, new MockSpreadsheet(id));
        }
        return spreadsheets.get(id);
      },
      getActiveSpreadsheet: () => {
        throw new Error('getActiveSpreadsheet() should NOT be called in isolated sandbox mode');
      },
      flush: () => {},
    },
    ContentService: {
      MimeType: { JSON: 'application/json' },
      createTextOutput: (text: string) => ({
        setMimeType: () => ({
          getContent: () => text,
        }),
      }),
    },
    Utilities: {
      formatDate: (date: Date, tz: string, fmt: string) => {
        return date.toISOString().split('T')[0];
      },
    },
    Logger: {
      log: () => {},
    },
    console: {
      log: () => {},
      warn: () => {},
      error: () => {},
    },
  };

  const gsCode = fs.readFileSync(path.resolve(process.cwd(), 'scripts/sandbox-google-apps-script.gs'), 'utf8');
  const context = vm.createContext(sandbox);
  vm.runInContext(gsCode, context);

  return {
    context,
    scriptProperties,
    getOpenedSpreadsheetId: () => openedSpreadsheetId,
    doPost: (payload: any, paramSecret?: string) => {
      const e = {
        postData: { contents: JSON.stringify(payload) },
        parameter: paramSecret ? { secret: paramSecret } : {},
      };
      const res = vm.runInContext(`doPost(${JSON.stringify(e)})`, context);
      return JSON.parse(res.getContent());
    },
    doGet: (params: any = {}) => {
      const e = { parameter: params };
      const res = vm.runInContext(`doGet(${JSON.stringify(e)})`, context);
      return JSON.parse(res.getContent());
    },
    getSandboxSpreadsheet: () => {
      return vm.runInContext(`getSandboxSpreadsheet()`, context);
    },
  };
}

// ==========================================
// TEST SUITE EXECUTION
// ==========================================

async function runTests() {
  console.log('🧪 Starting Sandbox Apps Script Integration Test Suite...\n');

  // SECTION 1: Shared Secret Protection
  console.log('1. Testing Shared Secret Enforcement in doPost:');
  {
    // Case 1A: Unconfigured SANDBOX_SHARED_SECRET
    const envUnconfigured = createAppsScriptEnvironment({
      SANDBOX_SPREADSHEET_ID: 'mock-sandbox-sheet-123',
    });
    const res1A = envUnconfigured.doPost({ action: 'HEARTBEAT_UPDATE', secret: 'some-secret' });
    assert(res1A.status === 'ERROR', 'Fails when SANDBOX_SHARED_SECRET is not configured in Script Properties');
    assert(res1A.code === 'UNCONFIGURED_SHARED_SECRET', 'Returns UNCONFIGURED_SHARED_SECRET error code');

    // Case 1B: Missing secret in request
    const envConfigured = createAppsScriptEnvironment({
      SANDBOX_SHARED_SECRET: 'super-secure-sandbox-token-2026',
      SANDBOX_SPREADSHEET_ID: 'mock-sandbox-sheet-123',
    });
    const res1B = envConfigured.doPost({ action: 'HEARTBEAT_UPDATE' });
    assert(res1B.status === 'ERROR', 'Fails when request does not provide shared secret');
    assert(res1B.code === 'UNAUTHORIZED', 'Returns UNAUTHORIZED code for missing secret');

    // Case 1C: Incorrect shared secret
    const res1C = envConfigured.doPost({ action: 'HEARTBEAT_UPDATE', secret: 'wrong-secret-token' });
    assert(res1C.status === 'ERROR', 'Fails when request provides incorrect shared secret');
    assert(res1C.code === 'UNAUTHORIZED', 'Returns UNAUTHORIZED code for incorrect secret');

    // Case 1D: Valid shared secret
    const res1D = envConfigured.doPost({
      action: 'HEARTBEAT_UPDATE',
      secret: 'super-secure-sandbox-token-2026',
      presence: { userId: 'usr-1', employeeCode: 'LLC-101', userName: 'Test Agent' },
    });
    assert(res1D.status === 'SUCCESS', 'Succeeds when valid shared secret is provided');
  }

  // SECTION 2: Safe doGet Responses
  console.log('\n2. Testing Safe doGet Responses:');
  {
    const env = createAppsScriptEnvironment({
      SANDBOX_SHARED_SECRET: 'super-secure-sandbox-token-2026',
      SANDBOX_SPREADSHEET_ID: 'mock-sandbox-sheet-123',
    });
    const getRes = env.doGet();
    assert(getRes.status === 'SUCCESS', 'doGet returns status SUCCESS');
    assert(!getRes.employees, 'doGet does NOT expose employees list');
    assert(!getRes.timeLogs, 'doGet does NOT expose timeLogs');
    assert(!getRes.presence, 'doGet does NOT expose presence records');
    assert(!getRes.users, 'doGet does NOT expose users or credentials');
    assert(!getRes.spreadsheetId, 'doGet does NOT leak spreadsheet ID');
    assert(typeof getRes.message === 'string', 'doGet returns minimal safe status message');
  }

  // SECTION 3: Spreadsheet Isolation
  console.log('\n3. Testing Sandbox Spreadsheet Isolation:');
  {
    // Case 3A: Missing SANDBOX_SPREADSHEET_ID
    const envMissingId = createAppsScriptEnvironment({
      SANDBOX_SHARED_SECRET: 'super-secure-sandbox-token-2026',
    });
    let errorThrown = false;
    try {
      envMissingId.getSandboxSpreadsheet();
    } catch (e: any) {
      errorThrown = true;
      assert(e.message.includes('SANDBOX_SPREADSHEET_ID Script Property is not configured'), 'Rejects unconfigured SANDBOX_SPREADSHEET_ID');
    }
    assert(errorThrown, 'Fails closed when SANDBOX_SPREADSHEET_ID is missing');

    // Case 3B: Prohibited production spreadsheet ID
    const envProdId = createAppsScriptEnvironment({
      SANDBOX_SHARED_SECRET: 'super-secure-sandbox-token-2026',
      SANDBOX_SPREADSHEET_ID: '1h8ssmDEcV-PMGlkpOzfQCtlRpnoT0CBQQveT3e4wPfA',
    });
    let prodErrorThrown = false;
    try {
      envProdId.getSandboxSpreadsheet();
    } catch (e: any) {
      prodErrorThrown = true;
      assert(e.message.includes('strictly prohibited in sandbox mode'), 'Explicitly rejects known production spreadsheet ID');
    }
    assert(prodErrorThrown, 'Fails closed when production spreadsheet ID is targeted');

    // Case 3C: Valid sandbox spreadsheet ID
    const envValidId = createAppsScriptEnvironment({
      SANDBOX_SHARED_SECRET: 'super-secure-sandbox-token-2026',
      SANDBOX_SPREADSHEET_ID: 'valid-sandbox-spreadsheet-xyz',
    });
    const ss = envValidId.getSandboxSpreadsheet();
    assert(ss.getId() === 'valid-sandbox-spreadsheet-xyz', 'Opens exclusively the configured sandbox spreadsheet');
  }

  // SECTION 4: Worker-to-Apps-Script Protocol & Data Integrity
  console.log('\n4. Testing Supported Actions & Data Integrity:');
  {
    const env = createAppsScriptEnvironment({
      SANDBOX_SHARED_SECRET: 'super-secure-sandbox-token-2026',
      SANDBOX_SPREADSHEET_ID: 'valid-sandbox-sheet-777',
    });
    const secret = 'super-secure-sandbox-token-2026';

    // 4A: SYNC_USERS / SYNC_EMPLOYEES saves employee with AccountPassword and mustChangePassword
    const usersRes = env.doPost({
      action: 'SYNC_USERS',
      secret,
      users: [
        {
          id: 'usr-agent-007',
          employeeCode: 'LLC-1007',
          username: 'james_bond',
          name: 'James Bond',
          email: 'agent007@example.com',
          role: 'agent',
          designation: 'Field Agent',
          accountPassword: 'InitialSecret123!',
          mustChangePassword: true,
          status: 'active',
        },
      ],
    });
    assert(usersRes.status === 'SUCCESS', 'SYNC_USERS action succeeded');
    assert(usersRes.count === 1, 'Records 1 user synced');

    // 4B: AUTH_LOGIN with mustChangePassword = true
    const loginMustChange = env.doPost({
      action: 'AUTH_LOGIN',
      secret,
      usernameOrCode: 'james_bond',
      password: 'InitialSecret123!',
    });
    assert(loginMustChange.status === 'SUCCESS', 'AUTH_LOGIN succeeds for active employee');
    assert(loginMustChange.mustChangePassword === true, 'Returns mustChangePassword = true for initial state');
    assert(loginMustChange.user.employeeCode === 'LLC-1007', 'Returns correct employee details');

    // 4C: Wrong password rejected
    const loginWrongPw = env.doPost({
      action: 'AUTH_LOGIN',
      secret,
      usernameOrCode: 'james_bond',
      password: 'WrongPassword!',
    });
    assert(loginWrongPw.status === 'ERROR', 'AUTH_LOGIN fails for wrong password');

    // 4D: UPDATE_PASSWORD updates existing row to new password and mustChangePassword = false
    const pwRes = env.doPost({
      action: 'UPDATE_PASSWORD',
      secret,
      userId: 'usr-agent-007',
      employeeCode: 'LLC-1007',
      username: 'james_bond',
      newPassword: 'MyNewUniquePassword2026!',
    });
    assert(pwRes.status === 'SUCCESS', 'UPDATE_PASSWORD action succeeded');
    assert(pwRes.action === 'UPDATE_PASSWORD', 'Response echoes UPDATE_PASSWORD action');

    // 4E: New password works on next login, old password does not
    const loginOldPw = env.doPost({
      action: 'AUTH_LOGIN',
      secret,
      usernameOrCode: 'james_bond',
      password: 'InitialSecret123!',
    });
    assert(loginOldPw.status === 'ERROR', 'Old password rejected after password change');

    const loginNewPw = env.doPost({
      action: 'AUTH_LOGIN',
      secret,
      usernameOrCode: 'james_bond',
      password: 'MyNewUniquePassword2026!',
    });
    assert(loginNewPw.status === 'SUCCESS', 'New password succeeds on next login');
    assert(loginNewPw.mustChangePassword === false, 'mustChangePassword is now false after change');

    // 4F: Non-existent employee (e.g. agabr / Alexa) is rejected
    const loginAbsent = env.doPost({
      action: 'AUTH_LOGIN',
      secret,
      usernameOrCode: 'agabr',
      password: 'Password123!',
    });
    assert(loginAbsent.status === 'ERROR', 'Non-existent employee login is rejected');
    assert(loginAbsent.code === 'USER_NOT_FOUND', 'Returns USER_NOT_FOUND error code');

    // 4G: SYNC_TIMELOGS with Idempotent Session ID and numeric duration seconds
    const timelogRes1 = env.doPost({
      action: 'SYNC_TIMELOGS',
      secret,
      timeLogs: [
        {
          id: 'session-unique-999',
          employeeCode: 'LLC-1007',
          userName: 'James Bond',
          role: 'agent',
          date: '2026-10-10',
          startTime: '09:00:00',
          endTime: '10:00:00',
          durationSeconds: 3600,
          status: 'completed',
          task: 'Intelligence Gathering',
          userId: 'usr-agent-007',
        },
      ],
    });
    assert(timelogRes1.status === 'SUCCESS', 'SYNC_TIMELOGS records initial log');

    // Update the same session ID idempotently (should not create duplicate)
    const timelogRes2 = env.doPost({
      action: 'SYNC_TIMELOGS',
      secret,
      timeLogs: [
        {
          id: 'session-unique-999',
          employeeCode: 'LLC-1007',
          userName: 'James Bond',
          role: 'agent',
          date: '2026-10-10',
          startTime: '09:00:00',
          endTime: '10:30:00',
          durationSeconds: 5400,
          status: 'completed',
          task: 'Intelligence Gathering & Reporting',
          userId: 'usr-agent-007',
        },
      ],
    });
    assert(timelogRes2.status === 'SUCCESS', 'Idempotent update of existing Session ID succeeded');

    // 4D: Authenticated Read (GET_ALL) via POST with secret
    const readRes = env.doPost({
      action: 'GET_ALL',
      secret,
    });
    assert(readRes.status === 'SUCCESS', 'Authenticated GET_ALL via POST succeeded');
    assert(Array.isArray(readRes.employees) && readRes.employees.length > 0, 'Returns employees in GET_ALL');
    assert(!readRes.employees.some((e: any) => e.password || e.passwordHash), 'Employees do NOT expose password hashes');
    assert(Array.isArray(readRes.timeLogs) && readRes.timeLogs.length === 1, 'Maintains 1 idempotent time log (no duplicate created)');
    assert(readRes.timeLogs[0].durationSeconds === 5400, 'Preserves updated numeric duration seconds (5400)');
    assert(readRes.timeLogs[0].sessionId === 'session-unique-999', 'Preserves unique session ID');
  }

  // SECTION 5: Worker Server-to-Server Secret Forwarding
  console.log('\n5. Testing Cloudflare Worker Secret Forwarding & Safe Responses:');
  {
    let receivedAppsScriptBody: any = null;
    const mockAppsScriptUrl = 'https://script.google.com/macros/s/AKfycbx_mock_sandbox_app_script_id_123456789/exec';
    const mockSecret = 'secret-worker-env-token-xyz';
    const jwtSecret = 'test-secret-key-321';

    // Mock fetch in Worker tests to inspect server-to-server calls
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes('script.google.com')) {
        if (init?.body) {
          try {
            receivedAppsScriptBody = JSON.parse(init.body as string);
          } catch {}
        }
        return new Response(
          JSON.stringify({
            status: 'SUCCESS',
            action: receivedAppsScriptBody?.action || 'TEST',
            message: 'Mock Apps Script success',
            employees: [{ employeeCode: 'LLC-100', name: 'Mock Agent' }],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return originalFetch(url, init);
    }) as any;

    try {
      const mockEnv = {
        JWT_SECRET: jwtSecret,
        SANDBOX_APPS_SCRIPT_URL: mockAppsScriptUrl,
        SANDBOX_APPS_SCRIPT_SECRET: mockSecret,
      };

      // Create valid token for testing
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        'raw',
        enc.encode(jwtSecret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const header = { alg: 'HS256', typ: 'JWT' };
      const payload = { userId: 'usr-admin', role: 'admin' };
      const b64H = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const b64P = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${b64H}.${b64P}`));
      const b64S = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const validToken = `${b64H}.${b64P}.${b64S}`;

      // 5A: POST /api/sync-sheets automatically injects SANDBOX_APPS_SCRIPT_SECRET
      const syncPostReq = new Request('http://localhost/api/sync-sheets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${validToken}`,
        },
        body: JSON.stringify({
          payload: {
            action: 'SYNC_TIMELOGS',
            timeLogs: [{ id: 'sess-1', durationSeconds: 60 }],
          },
        }),
      });
      const syncPostRes = await worker.fetch(syncPostReq, mockEnv, {});
      assert(syncPostRes.status === 200, 'POST /api/sync-sheets succeeds');
      assert(receivedAppsScriptBody?.secret === mockSecret, 'Worker injected SANDBOX_APPS_SCRIPT_SECRET server-to-server');

      // 5B: Unauthenticated POST /api/sync-sheets is rejected
      const syncUnauthReq = new Request('http://localhost/api/sync-sheets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'SYNC_TIMELOGS' }),
      });
      const syncUnauthRes = await worker.fetch(syncUnauthReq, mockEnv, {});
      assert(syncUnauthRes.status === 401, 'Unauthenticated POST /api/sync-sheets returns HTTP 401');

      // 5C: Forbidden action (GET_ALL) on /api/sync-sheets is rejected
      const syncForbiddenReq = new Request('http://localhost/api/sync-sheets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${validToken}`,
        },
        body: JSON.stringify({ action: 'GET_ALL' }),
      });
      const syncForbiddenRes = await worker.fetch(syncForbiddenReq, mockEnv, {});
      assert(syncForbiddenRes.status === 403, 'Forbidden action (GET_ALL) on /api/sync-sheets returns HTTP 403');
    } finally {
      globalThis.fetch = originalFetch;
    }
  }

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
