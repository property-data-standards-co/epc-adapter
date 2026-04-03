/**
 * EPC Adapter HTTP server — Hono.
 */
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { EpcClient, EpcApiError } from './epc-client.js';
import { EpcCredentialBuilder } from './credential-builder.js';
import { resolveDidKey } from '@pdtf/core';
import type { Config } from './config.js';
import { loadConfig } from './config.js';

export interface AppDeps {
  epcClient: EpcClient;
  builder: EpcCredentialBuilder;
  adapterDid: string;
}

export function createApp(deps: AppDeps): Hono {
  const app = new Hono();
  const { epcClient, builder, adapterDid } = deps;

  // ─── Health ──────────────────────────────────────────────────────────────

  app.get('/v1/health', (c) => {
    return c.json({ status: 'ok', service: 'epc-adapter', did: adapterDid });
  });

  // ─── DID Document ────────────────────────────────────────────────────────

  app.get('/.well-known/did.json', (c) => {
    // For did:key, derive the DID document
    if (adapterDid.startsWith('did:key:')) {
      const doc = resolveDidKey(adapterDid);
      return c.json(doc);
    }

    // For did:web, return a static DID document
    return c.json({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
      id: adapterDid,
      verificationMethod: [],
      assertionMethod: [],
    });
  });

  // ─── Issue credential by UPRN ────────────────────────────────────────────

  app.post('/v1/credential/uprn/:uprn', async (c) => {
    const uprn = c.req.param('uprn');

    if (!uprn || !/^\d+$/.test(uprn)) {
      return c.json({ error: 'Invalid UPRN — must be numeric' }, 400);
    }

    try {
      const { record, rawBody } = await epcClient.searchByUprn(uprn);
      const vc = await builder.buildCredential(record, rawBody);
      return c.json(vc);
    } catch (err) {
      return handleError(c, err);
    }
  });

  // ─── Issue credential by LMK key ────────────────────────────────────────

  app.post('/v1/credential/lmk/:lmkKey', async (c) => {
    const lmkKey = c.req.param('lmkKey');

    try {
      const { record, rawBody } = await epcClient.getCertificate(lmkKey);
      const vc = await builder.buildCredential(record, rawBody);
      return c.json(vc);
    } catch (err) {
      return handleError(c, err);
    }
  });

  return app;
}

function handleError(c: { json: (body: unknown, status: number) => Response }, err: unknown): Response {
  if (err instanceof EpcApiError) {
    return c.json({ error: err.message }, err.statusCode as 404);
  }
  console.error('Unexpected error:', err);
  return c.json({ error: 'Internal server error' }, 500);
}

// ─── Standalone server ─────────────────────────────────────────────────────

if (process.argv[1]?.endsWith('server.ts') || process.argv[1]?.endsWith('server.js')) {
  const config = loadConfig();

  const epcClient = new EpcClient({
    email: config.epcApiEmail,
    apiKey: config.epcApiKey,
    baseUrl: config.epcApiBaseUrl,
    maxRetries: config.epcApiMaxRetries,
  });

  const builder = new EpcCredentialBuilder({
    signingKeyHex: config.signingKeyHex,
    adapterDid: config.adapterDid || undefined,
    signingKeyId: config.signingKeyId,
  });

  const adapterDid = builder.adapterDid;

  const app = createApp({ epcClient, builder, adapterDid });

  console.log(`EPC Adapter starting on port ${config.port}`);
  console.log(`Adapter DID: ${adapterDid}`);

  serve({ fetch: app.fetch, port: config.port });
}
