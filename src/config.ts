/**
 * Environment-driven configuration for the EPC adapter.
 */
export interface Config {
  /** EPC Register API email */
  epcApiEmail: string;
  /** EPC Register API key */
  epcApiKey: string;
  /** Base URL for EPC API */
  epcApiBaseUrl: string;
  /** Max retries on 429/5xx */
  epcApiMaxRetries: number;
  /** Hex-encoded Ed25519 secret key (64 chars) */
  signingKeyHex: string;
  /** Adapter DID (derived from signing key if not set) */
  adapterDid: string;
  /** Signing key ID */
  signingKeyId: string;
  /** HTTP port */
  port: number;
}

export function loadConfig(): Config {
  const signingKeyHex = requireEnv('SIGNING_KEY_HEX');

  return {
    epcApiEmail: requireEnv('EPC_API_EMAIL'),
    epcApiKey: requireEnv('EPC_API_KEY'),
    epcApiBaseUrl: process.env.EPC_API_BASE_URL ?? 'https://epc.opendatacommunities.org/api/v1',
    epcApiMaxRetries: parseInt(process.env.EPC_API_MAX_RETRIES ?? '2', 10),
    signingKeyHex,
    adapterDid: process.env.ADAPTER_DID ?? '',  // resolved at init from key if empty
    signingKeyId: 'epc-adapter',
    port: parseInt(process.env.PORT ?? '8081', 10),
  };
}

function requireEnv(name: string): string {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required env var: ${name}`);
  return val;
}
