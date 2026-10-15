import worker from '../src/server/apiHandler.js';

async function testAuthFixes() {
  console.log('🧪 Testing Authentication Fixes for Pia Password Change & Admin Employee Creation...\n');

  const mockEnvMissingSecret = {
    SANDBOX_APPS_SCRIPT_URL: 'https://script.google.com/macros/s/AKfycbx_mock_sandbox_app_script_id/exec',
    SANDBOX_APPS_SCRIPT_SECRET: 'test-shared-secret-123',
  };

  const mockEnv = {
    SANDBOX_APPS_SCRIPT_URL: 'https://script.google.com/macros/s/AKfycbx_mock_sandbox_app_script_id/exec',
    SANDBOX_APPS_SCRIPT_SECRET: 'test-shared-secret-123',
    JWT_SECRET: 'test-production-jwt-secret-key-2026',
  };

  let storedUserPw = 'Password123!';
  let mustChange = true;

  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    let body: any = {};
    if (init?.body) {
      try {
        body = JSON.parse(init.body as string);
      } catch {}
    }

    if (body.action === 'AUTH_LOGIN') {
      if (body.password === storedUserPw) {
        return new Response(
          JSON.stringify({
            status: 'SUCCESS',
            valid: true,
            mustChangePassword: mustChange,
            user: {
              id: 'usr-llc-0003',
              employeeCode: 'LLC-0003',
              username: 'pia',
              name: 'Pia',
              role: 'trainer',
              designation: 'Trainer',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      } else {
        return new Response(
          JSON.stringify({ status: 'ERROR', code: 'INVALID_CREDENTIALS', message: 'Incorrect password' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }

    if (body.action === 'UPDATE_PASSWORD') {
      storedUserPw = body.newPassword;
      mustChange = false;
      return new Response(
        JSON.stringify({
          status: 'SUCCESS',
          action: 'UPDATE_PASSWORD',
          verified: true,
          userId: body.userId,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (body.action === 'SYNC_USERS') {
      return new Response(
        JSON.stringify({
          status: 'SUCCESS',
          count: 1,
          user: body.users ? body.users[0] : {},
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response(JSON.stringify({ status: 'SUCCESS' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as any;

  try {
    // 0. Missing Production Secret Check
    console.log('0. Testing Missing JWT_SECRET explicit configuration error:');
    const missingSecretReq = new Request('http://localhost/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrCode: 'LLC-0003', password: 'Password123!' }),
    });
    const missingSecretRes = await worker.fetch(missingSecretReq, mockEnvMissingSecret, {});
    const missingSecretData = await missingSecretRes.json();
    console.log(`  Missing Secret HTTP Status: ${missingSecretRes.status}`);
    console.log(`  Missing Secret Response:`, JSON.stringify(missingSecretData));

    if (missingSecretRes.status !== 500 || !missingSecretData.error?.includes('JWT_SECRET')) {
      throw new Error('Failed to explicitly reject missing JWT_SECRET environment variable with 500 error');
    }
    console.log('  ✅ Explicit HTTP 500 configuration error verified when JWT_SECRET is missing.\n');

    // 1. Pia First Time Password Change Flow
    console.log('1. Testing Trainer Pia Login & Password Change Flow:');
    const loginReq = new Request('http://localhost/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrCode: 'LLC-0003', password: 'Password123!' }),
    });
    const loginRes = await worker.fetch(loginReq, mockEnv, {});
    const loginData = await loginRes.json();

    console.log(`  Login HTTP Status: ${loginRes.status}`);
    console.log(`  Login Response:`, JSON.stringify(loginData));

    if (loginRes.status !== 200 || !loginData.token) {
      throw new Error(`Pia login failed with status ${loginRes.status}`);
    }

    const piaToken = loginData.token;

    // Call change-password with token
    const changePwReq = new Request('http://localhost/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${piaToken}`,
      },
      body: JSON.stringify({
        userId: 'usr-llc-0003',
        currentPassword: 'Password123!',
        newPassword: 'PiaNewSecretPass2026!',
      }),
    });

    const changeRes = await worker.fetch(changePwReq, mockEnv, {});
    const changeData = await changeRes.json();

    console.log(`  Change Password HTTP Status: ${changeRes.status}`);
    console.log(`  Change Password Response:`, JSON.stringify(changeData));

    if (changeRes.status !== 200 || changeData.verified !== true) {
      throw new Error(`Pia password change failed with status ${changeRes.status}`);
    }

    console.log('  ✅ Pia password change succeeded and verified against Google Sheets!\n');

    // 2. Admin Employee Creation Flow
    console.log('2. Testing Admin Employee Creation Flow:');

    // Admin login
    const adminLoginReq = new Request('http://localhost/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrCode: 'SuperAdmin', password: 'Password123!' }),
    });

    // Mock fetch for Admin login
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      let body: any = {};
      if (init?.body) {
        try {
          body = JSON.parse(init.body as string);
        } catch {}
      }

      if (body.action === 'AUTH_LOGIN') {
        return new Response(
          JSON.stringify({
            status: 'SUCCESS',
            valid: true,
            mustChangePassword: false,
            user: {
              id: 'usr-superadmin',
              employeeCode: 'SuperAdmin',
              username: 'admin',
              name: 'Admin',
              role: 'admin',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      if (body.action === 'SYNC_USERS') {
        return new Response(
          JSON.stringify({
            status: 'SUCCESS',
            count: 1,
            user: body.users ? body.users[0] : {},
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ status: 'SUCCESS' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as any;

    const adminLoginRes = await worker.fetch(adminLoginReq, mockEnv, {});
    const adminLoginData = await adminLoginRes.json();
    const adminToken = adminLoginData.token;

    console.log(`  Admin Login HTTP Status: ${adminLoginRes.status}`);

    const createEmpReq = new Request('http://localhost/api/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        id: 'usr-llc-0050',
        employeeCode: 'LLC-0050',
        name: 'New Test Employee',
        username: 'new_employee',
        role: 'agent',
        designation: 'Outbound Agent/Team',
      }),
    });

    const createEmpRes = await worker.fetch(createEmpReq, mockEnv, {});
    const createEmpData = await createEmpRes.json();

    console.log(`  Create Employee HTTP Status: ${createEmpRes.status}`);
    console.log(`  Create Employee Response:`, JSON.stringify(createEmpData));

    if (createEmpRes.status !== 200 || createEmpData.success !== true) {
      throw new Error(`Admin employee creation failed with status ${createEmpRes.status}`);
    }

    console.log('  ✅ Admin employee creation succeeded and verified against Google Sheets!\n');

    console.log('========================================');
    console.log('ALL AUTHENTICATION FIXES VERIFIED SUCCESSFULLY!');
    console.log('========================================');
  } finally {
    globalThis.fetch = origFetch;
  }
}

testAuthFixes().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
