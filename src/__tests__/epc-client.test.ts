import { describe, it, expect, vi } from 'vitest';
import { EpcClient, EpcApiError } from '../epc-client.js';
import mockResponse from '../../mocks/epc-response.json' with { type: 'json' };

function mockFetch(response: unknown, status = 200, headers: Record<string, string> = {}) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: {
      get: (key: string) => headers[key] ?? null,
    },
    text: async () => JSON.stringify(response),
  });
}

describe('EpcClient', () => {
  const opts = { email: 'test@example.com', apiKey: 'abc123' };

  it('constructs Basic auth header correctly', async () => {
    const fetchFn = mockFetch({ rows: [mockResponse], 'column-names': [] });
    const client = new EpcClient({ ...opts, fetchFn });

    await client.searchByUprn('100023336956');

    const call = fetchFn.mock.calls[0];
    const expectedToken = Buffer.from('test@example.com:abc123').toString('base64');
    expect(call[1].headers.Authorization).toBe(`Basic ${expectedToken}`);
    expect(call[1].headers.Accept).toBe('application/json');
  });

  it('searchByUprn returns first row', async () => {
    const fetchFn = mockFetch({ rows: [mockResponse], 'column-names': [] });
    const client = new EpcClient({ ...opts, fetchFn });

    const result = await client.searchByUprn('100023336956');

    expect(result.record['lmk-key']).toBe('0000-0000-0000-0000-0000');
    expect(result.record.uprn).toBe('100023336956');
    expect(result.rawBody).toContain('100023336956');
  });

  it('searchByUprn encodes UPRN in URL', async () => {
    const fetchFn = mockFetch({ rows: [mockResponse], 'column-names': [] });
    const client = new EpcClient({ ...opts, fetchFn });

    await client.searchByUprn('100023336956');

    expect(fetchFn.mock.calls[0][0]).toContain('uprn=100023336956');
    expect(fetchFn.mock.calls[0][0]).toContain('size=1');
  });

  it('getCertificate returns row by LMK key', async () => {
    const fetchFn = mockFetch({ rows: [mockResponse], 'column-names': [] });
    const client = new EpcClient({ ...opts, fetchFn });

    const result = await client.getCertificate('0000-0000-0000-0000-0000');

    expect(result.record['current-energy-rating']).toBe('D');
    expect(fetchFn.mock.calls[0][0]).toContain('/domestic/certificate/0000-0000-0000-0000-0000');
  });

  it('throws EpcApiError on 404', async () => {
    const fetchFn = mockFetch(null, 404);
    const client = new EpcClient({ ...opts, fetchFn });

    await expect(client.searchByUprn('000')).rejects.toThrow(EpcApiError);
    await expect(client.searchByUprn('000')).rejects.toThrow('not found');
  });

  it('throws EpcApiError on empty rows', async () => {
    const fetchFn = mockFetch({ rows: [], 'column-names': [] });
    const client = new EpcClient({ ...opts, fetchFn });

    await expect(client.searchByUprn('000')).rejects.toThrow('No EPC found');
  });

  it('throws EpcApiError on 500', async () => {
    const fetchFn = mockFetch(null, 500);
    const client = new EpcClient({ ...opts, fetchFn });

    await expect(client.getCertificate('bad')).rejects.toThrow('EPC API error: 500');
  });

  it('retries on 429', async () => {
    let calls = 0;
    const fetchFn = vi.fn().mockImplementation(async () => {
      calls++;
      if (calls === 1) {
        return {
          ok: false,
          status: 429,
          statusText: 'Too Many Requests',
          headers: { get: (k: string) => (k === 'Retry-After' ? '0' : null) },
          text: async () => '{}',
        };
      }
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: { get: () => null },
        text: async () => JSON.stringify({ rows: [mockResponse], 'column-names': [] }),
      };
    });

    const client = new EpcClient({ ...opts, fetchFn, maxRetries: 2 });
    const result = await client.searchByUprn('100023336956');

    expect(calls).toBe(2);
    expect(result.record['lmk-key']).toBe('0000-0000-0000-0000-0000');
  });
});
