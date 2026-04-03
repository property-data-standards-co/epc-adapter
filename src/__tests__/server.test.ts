import { describe, it, expect, vi } from 'vitest';
import { createApp, type AppDeps } from '../server.js';
import { EpcCredentialBuilder } from '../credential-builder.js';
import { EpcClient, EpcApiError } from '../epc-client.js';
import mockResponse from '../../mocks/epc-response.json' with { type: 'json' };
import type { EpcRecord } from '../epc-client.js';

const TEST_SECRET_HEX = 'abababababababababababababababababababababababababababababababab';

function createTestDeps(overrides: Partial<AppDeps> = {}): AppDeps {
  const builder = new EpcCredentialBuilder({ signingKeyHex: TEST_SECRET_HEX });

  const mockFetchFn = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: { get: () => null },
    text: async () => JSON.stringify({ rows: [mockResponse], 'column-names': [] }),
  });

  const epcClient = new EpcClient({
    email: 'test@test.com',
    apiKey: 'key',
    fetchFn: mockFetchFn,
  });

  return {
    epcClient,
    builder,
    adapterDid: builder.adapterDid,
    ...overrides,
  };
}

describe('Server', () => {
  it('GET /v1/health returns ok', async () => {
    const app = createApp(createTestDeps());
    const res = await app.request('/v1/health');
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.service).toBe('epc-adapter');
    expect(body.did).toMatch(/^did:key:z6Mk/);
  });

  it('GET /.well-known/did.json returns DID document for did:key', async () => {
    const app = createApp(createTestDeps());
    const res = await app.request('/.well-known/did.json');
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.id).toMatch(/^did:key:z6Mk/);
    expect(body.verificationMethod).toBeDefined();
    expect(body.assertionMethod).toBeDefined();
  });

  it('POST /v1/credential/uprn/:uprn returns signed VC', async () => {
    const app = createApp(createTestDeps());
    const res = await app.request('/v1/credential/uprn/100023336956', { method: 'POST' });
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.type).toContain('VerifiableCredential');
    expect(body.type).toContain('EnergyPerformanceCertificate');
    expect(body.credentialSubject.id).toBe('urn:pdtf:uprn:100023336956');
    expect(body.proof).toBeDefined();
    expect(body.proof.type).toBe('DataIntegrityProof');
  });

  it('POST /v1/credential/lmk/:lmkKey returns signed VC', async () => {
    const app = createApp(createTestDeps());
    const res = await app.request('/v1/credential/lmk/0000-0000-0000-0000-0000', { method: 'POST' });
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.type).toContain('EnergyPerformanceCertificate');
    expect(body.id).toBe('urn:pdtf:epc:0000-0000-0000-0000-0000');
  });

  it('POST /v1/credential/uprn/:uprn returns 400 for non-numeric UPRN', async () => {
    const app = createApp(createTestDeps());
    const res = await app.request('/v1/credential/uprn/abc', { method: 'POST' });
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain('Invalid UPRN');
  });

  it('POST /v1/credential/uprn/:uprn returns 404 when EPC not found', async () => {
    const mockFetchFn = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      headers: { get: () => null },
      text: async () => '{}',
    });
    const epcClient = new EpcClient({ email: 'a', apiKey: 'b', fetchFn: mockFetchFn });
    const builder = new EpcCredentialBuilder({ signingKeyHex: TEST_SECRET_HEX });
    const app = createApp({ epcClient, builder, adapterDid: builder.adapterDid });

    const res = await app.request('/v1/credential/uprn/999999999999', { method: 'POST' });
    const body = await res.json();

    expect(res.status).toBe(404);
    expect(body.error).toContain('not found');
  });
});
