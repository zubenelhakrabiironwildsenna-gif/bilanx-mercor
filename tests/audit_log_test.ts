import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from '../src/server/app.ts';
import { generateProof } from '../src/lib/crypto/zkp/nizkp.ts';
import { globalSessionStore } from '../src/server/sessionManager.ts';
import { clearAccessLogs } from '../src/server/accessLogDb.ts';

describe('Audit Log Security & Functional Integrity', () => {
  test('audit log enforces auth, prevents sessionToken leaks, and records COMPLIANCE_RUN events', async () => {
    await clearAccessLogs();
    globalSessionStore.clear();

    const app = createApp({ isTest: true });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        throw new Error('Failed to resolve test server address');
      }
      const baseUrl = `http://127.0.0.1:${addr.port}`;

      // 1. Unauthenticated access to all audit endpoints & record-event must fail closed (401)
      for (const [method, endpoint] of [
        ['GET', '/api/access-logs'],
        ['GET', '/api/access-logs/stats'],
        ['GET', '/api/access-logs/export'],
        ['POST', '/api/access-logs/clear'],
        ['POST', '/api/auth/record-event'],
      ] as const) {
        const res = await fetch(`${baseUrl}${endpoint}`, {
          method,
          headers: method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
          body: method === 'POST' ? JSON.stringify({ action: 'APP_ACCESS' }) : undefined,
        });
        assert.equal(res.status, 401, `${method} ${endpoint} must reject unauthenticated callers`);
      }

      // 2. SAML ACS login must NEVER write raw sessionToken into user.uid or audit logs
      const samlRes = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: 'swiss_adult' }),
      });
      assert.equal(samlRes.status, 200);
      const samlData = await samlRes.json();
      assert.ok(samlData.sessionToken, 'Expected sessionToken from /saml/acs');
      assert.notEqual(samlData.user.uid, samlData.sessionToken, 'SAML user.uid must not equal raw sessionToken');
      assert.ok(samlData.user.uid.startsWith('saml-'), 'SAML audit UID must be an opaque saml-* digest');

      const authHeaders = {
        Authorization: `Bearer ${samlData.sessionToken}`,
        'Content-Type': 'application/json',
      };

      // 3. ZKP age-gate verification records COMPLIANCE_RUN (both valid and invalid)
      const validProof = await generateProof(25, 18);
      const verifyOk = await fetch(`${baseUrl}/api/v1/age-gate/verify`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ proofBase64: Buffer.from(validProof).toString('base64') }),
      });
      assert.equal(verifyOk.status, 200);
      assert.equal((await verifyOk.json()).valid, true);

      const badProof = new Uint8Array(validProof);
      badProof[20] ^= 0xff;
      const verifyBad = await fetch(`${baseUrl}/api/v1/age-gate/verify`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ proofBase64: Buffer.from(badProof).toString('base64') }),
      });
      assert.equal(verifyBad.status, 200);
      assert.equal((await verifyBad.json()).valid, false);

      // 4. Query filtered COMPLIANCE_RUN audit logs and verify zero sessionToken exposure
      const logsRes = await fetch(`${baseUrl}/api/access-logs?action=COMPLIANCE_RUN`, {
        headers: { Authorization: `Bearer ${samlData.sessionToken}` },
      });
      assert.equal(logsRes.status, 200);
      const logsBody = await logsRes.json();
      assert.equal(logsBody.total, 2, 'Expected 2 COMPLIANCE_RUN events');
      assert.equal(logsBody.logs[0].status, 'DENIED');
      assert.equal(logsBody.logs[1].status, 'SUCCESS');

      const allLogsRes = await fetch(`${baseUrl}/api/access-logs`, {
        headers: { Authorization: `Bearer ${samlData.sessionToken}` },
      });
      const allLogsRaw = await allLogsRes.text();
      assert.equal(
        allLogsRaw.includes(samlData.sessionToken),
        false,
        'Raw sessionToken must never appear in audit logs'
      );

      // 5. CSV export and stats work for authenticated callers
      const statsRes = await fetch(`${baseUrl}/api/access-logs/stats`, {
        headers: { Authorization: `Bearer ${samlData.sessionToken}` },
      });
      assert.equal(statsRes.status, 200);
      const stats = await statsRes.json();
      assert.ok(stats.totalAccesses >= 3);

      const csvRes = await fetch(`${baseUrl}/api/access-logs/export`, {
        headers: { Authorization: `Bearer ${samlData.sessionToken}` },
      });
      assert.equal(csvRes.status, 200);
      const csvText = await csvRes.text();
      assert.ok(csvText.includes('COMPLIANCE_RUN'));
      assert.equal(csvText.includes(samlData.sessionToken), false, 'CSV export must never leak sessionToken');
    } finally {
      server.close();
      await clearAccessLogs();
    }
  });
});
