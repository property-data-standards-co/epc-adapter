/**
 * Transforms raw EPC data into a signed PDTF Verifiable Credential.
 */
import { createHash } from 'node:crypto';
import type { EpcRecord } from './epc-client.js';
import { VcSigner } from '@pdtf/core';
import type { KeyProvider, KeyCategory, KeyRecord } from '@pdtf/core';
import { ed25519 } from '@noble/curves/ed25519';
import { deriveDidKey } from '@pdtf/core';

// ─── Static Key Provider ─────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export class StaticKeyProvider implements KeyProvider {
  private readonly secretKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private readonly did: string;

  constructor(secretKeyHex: string) {
    this.secretKey = hexToBytes(secretKeyHex);
    this.publicKey = ed25519.getPublicKey(this.secretKey);
    this.did = deriveDidKey(this.publicKey);
  }

  async generateKey(keyId: string, category: KeyCategory): Promise<KeyRecord> {
    return {
      keyId,
      did: this.did,
      publicKey: this.publicKey,
      category,
      createdAt: new Date().toISOString(),
    };
  }

  async sign(_keyId: string, data: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(data, this.secretKey);
  }

  async getPublicKey(_keyId: string): Promise<Uint8Array> {
    return this.publicKey;
  }

  async resolveDidKey(_keyId: string): Promise<string> {
    return this.did;
  }

  getDid(): string {
    return this.did;
  }
}

// ─── Credential Builder ──────────────────────────────────────────────────────

export interface CredentialBuilderOptions {
  signingKeyHex: string;
  adapterDid?: string;
  signingKeyId?: string;
}

export class EpcCredentialBuilder {
  private readonly signer: VcSigner;
  private readonly keyId: string;
  readonly adapterDid: string;

  constructor(options: CredentialBuilderOptions) {
    const keyProvider = new StaticKeyProvider(options.signingKeyHex);
    this.adapterDid = options.adapterDid || keyProvider.getDid();
    this.keyId = options.signingKeyId ?? 'epc-adapter';
    this.signer = new VcSigner(keyProvider, this.keyId, this.adapterDid);
  }

  /**
   * Build and sign a PDTF Verifiable Credential from an EPC record.
   */
  async buildCredential(record: EpcRecord, rawBody: string): Promise<Record<string, unknown>> {
    const fetchedAt = new Date().toISOString();
    const sourceHash = createHash('sha256').update(rawBody).digest('hex');
    const lmkKey = record['lmk-key'];
    const uprn = record.uprn;
    const lodgementDate = record['lodgement-datetime'] || record['lodgement-date'];

    // EPCs are valid for 10 years from lodgement
    const validUntil = computeValidUntil(record['lodgement-date']);

    const vc = await this.signer.sign({
      id: `urn:pdtf:epc:${lmkKey}`,
      type: 'EnergyPerformanceCertificate',
      validFrom: lodgementDate,
      validUntil,
      credentialSubject: {
        id: `urn:pdtf:uprn:${uprn}`,
        certificate: {
          lmkKey,
          inspectionDate: record['inspection-date'],
          lodgementDate: record['lodgement-date'],
        },
        rating: {
          current: record['current-energy-rating'],
          currentScore: parseNum(record['current-energy-efficiency']),
          potential: record['potential-energy-rating'],
          potentialScore: parseNum(record['potential-energy-efficiency']),
        },
        property: {
          type: record['property-type'],
          builtForm: record['built-form'],
          totalFloorArea: parseNum(record['total-floor-area']),
        },
        address: {
          line1: record.address1,
          line2: record.address2 || undefined,
          line3: record.address3 || undefined,
          postcode: record.postcode,
          posttown: record.posttown,
          localAuthority: record['local-authority'],
          constituency: record.constituency,
        },
        fabric: {
          walls: record['walls-description'],
          roof: record['roof-description'],
          floor: record['floor-description'],
          windows: record['windows-description'],
        },
        heating: {
          description: record['main-heating-description'],
          mainFuel: record['main-fuel'],
        },
        environment: {
          co2Current: parseNum(record['co2-emissions-current']),
          co2Potential: parseNum(record['co2-emissions-potential']),
          co2PerFloorArea: parseNum(record['co2-emiss-curr-per-floor-area']),
          impactCurrent: parseNum(record['environment-impact-current']),
          impactPotential: parseNum(record['environment-impact-potential']),
          energyConsumptionCurrent: parseNum(record['energy-consumption-current']),
          energyConsumptionPotential: parseNum(record['energy-consumption-potential']),
        },
        costs: {
          heatingCurrent: parseNum(record['heating-cost-current']),
          heatingPotential: parseNum(record['heating-cost-potential']),
          hotWaterCurrent: parseNum(record['hot-water-cost-current']),
          hotWaterPotential: parseNum(record['hot-water-cost-potential']),
          lightingCurrent: parseNum(record['lighting-cost-current']),
          lightingPotential: parseNum(record['lighting-cost-potential']),
        },
      },
      evidence: [
        {
          type: 'ElectronicRecord',
          sourceUrl: `https://epc.opendatacommunities.org/api/v1/domestic/certificate/${lmkKey}`,
          fetchedAt,
          sourceHash,
        },
      ],
    });

    return vc as unknown as Record<string, unknown>;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parseNum(val: string | undefined): number | undefined {
  if (!val || val === '' || val === 'NO DATA!' || val === 'N/A' || val === 'INVALID!') return undefined;
  const n = parseFloat(val);
  return isNaN(n) ? undefined : n;
}

function computeValidUntil(lodgementDate: string): string {
  const d = new Date(lodgementDate);
  d.setFullYear(d.getFullYear() + 10);
  return d.toISOString().split('T')[0];
}
