import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import http, { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  createApp,
  getEffectiveHost,
  getEffectiveProtocol,
  getEffectiveRpId,
  getValidatedWebAuthnOrigin
} from '../src/server/app.ts';
import { runPilotDemonstration } from '../src/sandbox/lib/e2e/runSwissDemonstration.ts';
import { DEFAULT_UHD_RFID_ASSERTIONS } from '../src/data.ts';

function makeMockReq(headers: Record<string, string>, hostname = 'localhost', protocol = 'http'): any {
  return {
    headers,
    hostname,
    protocol,
    get(name: string) {
      return headers[name.toLowerCase()];
    }
  };
}

/**
 * Simulates the container Nginx reverse proxy (`Host: localhost:3000`,
 * `X-Forwarded-Host: <proxyHost>`, `X-Forwarded-Proto: https`) against an
 * ephemeral HTTP server on 127.0.0.1:<port>.
 */
function createNginxProxiedFetch(port: number, proxyHost: string): typeof fetch {
  return (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${proxyHost}${rawUrl}`);
    const method = init?.method || 'GET';
    const reqHeaders: Record<string, string> = {
      host: 'localhost:3000',
      'x-forwarded-host': proxyHost,
      'x-forwarded-proto': 'https',
      origin: `https://${proxyHost}`
    };

    if (init?.headers) {
      const h = new Headers(init.headers);
      h.forEach((value, key) => {
        reqHeaders[key.toLowerCase()] = value;
      });
    }

    const bodyStr = typeof init?.body === 'string' ? init.body : undefined;
    if (bodyStr && !reqHeaders['content-length']) {
      reqHeaders['content-length'] = String(Buffer.byteLength(bodyStr));
    }

    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port,
          path: parsed.pathname + parsed.search,
          method,
          headers: reqHeaders
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          res.on('end', () => {
            const buf = Buffer.concat(chunks);
            const resHeaders = new Headers();
            for (const [k, v] of Object.entries(res.headers)) {
              if (typeof v === 'string') resHeaders.set(k, v);
              else if (Array.isArray(v)) resHeaders.set(k, v.join(', '));
            }
            resolve(new Response(buf, { status: res.statusCode || 500, headers: resHeaders }));
          });
        }
      );
      req.on('error', reject);
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  };
}

describe('Reverse-Proxy WebAuthn Origin & RP ID Hardening (Step 2 E2E)', () => {
  test('proxy header helpers extract effective host, protocol, and RP ID safely', () => {
    const proxiedReq = makeMockReq({
      host: 'localhost:3000',
      'x-forwarded-host': 'ais-dev-sample.europe-west1.run.app',
      'x-forwarded-proto': 'https',
      origin: 'https://ais-dev-sample.europe-west1.run.app'
    });

    assert.equal(getEffectiveHost(proxiedReq), 'ais-dev-sample.europe-west1.run.app');
    assert.equal(getEffectiveProtocol(proxiedReq), 'https');
    assert.equal(getEffectiveRpId(proxiedReq), 'ais-dev-sample.europe-west1.run.app');
    assert.equal(getValidatedWebAuthnOrigin(proxiedReq), 'https://ais-dev-sample.europe-west1.run.app');

    // Spoofed origin behind proxy must fail closed
    const spoofedOriginReq = makeMockReq({
      host: 'localhost:3000',
      'x-forwarded-host': 'ais-dev-sample.europe-west1.run.app',
      'x-forwarded-proto': 'https',
      origin: 'https://malicious-phishing-attacker.ch'
    });
    assert.equal(getValidatedWebAuthnOrigin(spoofedOriginReq), null);

    // Invalid X-Forwarded-Host injection must be ignored
    const injectedHostReq = makeMockReq({
      host: '127.0.0.1:3000',
      'x-forwarded-host': 'evil.attacker.ch/redirect',
      'x-forwarded-proto': 'https',
      origin: 'https://evil.attacker.ch'
    });
    assert.equal(getEffectiveHost(injectedHostReq), '127.0.0.1:3000');
    assert.equal(getValidatedWebAuthnOrigin(injectedHostReq), null);
  });

  test('Swiss (CH) & Italian (IT) demos pass Step 2 behind Nginx proxy in simulator & CTAP2 modes', async () => {
    const app = createApp({ isTest: true });
    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));

    try {
      const port = (server.address() as AddressInfo).port;
      const proxyHost = 'ais-dev-hy64avsx437jbvrs3nvjb6-733444213216.europe-west1.run.app';
      const proxyOrigin = `https://${proxyHost}`;
      const proxiedFetch = createNginxProxiedFetch(port, proxyHost);
      const authenticProduct = DEFAULT_UHD_RFID_ASSERTIONS.find((r) => r.status === 'authentic')!;

      // 1. Swiss Demo (CH) — Platform Simulator
      const chSim = await runPilotDemonstration({
        jurisdiction: 'CH',
        citizenPreset: 'swiss_adult',
        authenticatorMode: 'platform_simulator',
        rfidAssertion: authenticProduct,
        baseUrl: proxyOrigin,
        fetchFn: proxiedFetch
      });
      assert.equal(chSim.success, true, `CH simulator failed: ${chSim.error}`);
      assert.equal(chSim.validationStatus, 'APPROVED');
      assert.ok(chSim.hwFingerprint.startsWith('HE-P256-'));

      // 2. Swiss Demo (CH) — YubiKey CTAP2
      const chCtap2 = await runPilotDemonstration({
        jurisdiction: 'CH',
        citizenPreset: 'swiss_adult',
        authenticatorMode: 'ctap2_hardware_key',
        useCtap2HardwareKey: true,
        rfidAssertion: authenticProduct,
        baseUrl: proxyOrigin,
        fetchFn: proxiedFetch
      });
      assert.equal(chCtap2.success, true, `CH CTAP2 failed: ${chCtap2.error}`);
      assert.equal(chCtap2.validationStatus, 'APPROVED');
      assert.ok(chCtap2.hwFingerprint.startsWith('HE-YUBIKEY-'));

      // 3. Italian Demo (IT) — Platform Simulator
      const itSim = await runPilotDemonstration({
        jurisdiction: 'IT',
        citizenPreset: 'it_adult_high',
        authenticatorMode: 'platform_simulator',
        rfidAssertion: authenticProduct,
        baseUrl: proxyOrigin,
        fetchFn: proxiedFetch
      });
      assert.equal(itSim.success, true, `IT simulator failed: ${itSim.error}`);
      assert.equal(itSim.validationStatus, 'APPROVED');
      assert.ok(itSim.hwFingerprint.startsWith('HE-P256-'));

      // 4. Italian Demo (IT) — YubiKey CTAP2
      const itCtap2 = await runPilotDemonstration({
        jurisdiction: 'IT',
        citizenPreset: 'it_adult_high',
        authenticatorMode: 'ctap2_hardware_key',
        useCtap2HardwareKey: true,
        rfidAssertion: authenticProduct,
        baseUrl: proxyOrigin,
        fetchFn: proxiedFetch
      });
      assert.equal(itCtap2.success, true, `IT CTAP2 failed: ${itCtap2.error}`);
      assert.equal(itCtap2.validationStatus, 'APPROVED');
      assert.ok(itCtap2.hwFingerprint.startsWith('HE-YUBIKEY-'));

      // 5. Verify hostile Origin is STILL rejected with HTTP 400 behind proxy
      const evilRes = await proxiedFetch(`${proxyOrigin}/api/webauthn/register-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://malicious-phishing-attacker.ch'
        },
        body: JSON.stringify({
          username: 'victim@bilanx.ch',
          credential: { id: 'evil-cred', response: { clientDataJSON: 'e30' } }
        })
      });
      assert.equal(evilRes.status, 400);
      const evilBody = await evilRes.json();
      assert.equal(evilBody.verified, false);
      assert.equal(evilBody.error, 'Origin mismatch or untrusted origin');
    } finally {
      server.close();
    }
  });
});
