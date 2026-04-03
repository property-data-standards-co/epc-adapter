/**
 * Transforms raw EPC data into a signed PDTF PropertyCredential
 * per Sub-spec 02: Verifiable Credentials Data Model.
 */
import { randomUUID } from 'node:crypto';
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
  /** Status list base URL for credentialStatus */
  statusListBaseUrl?: string;
}

export class EpcCredentialBuilder {
  private readonly signer: VcSigner;
  private readonly keyId: string;
  readonly adapterDid: string;
  private readonly statusListBaseUrl: string;
  private statusListIndex = 0;

  constructor(options: CredentialBuilderOptions) {
    const keyProvider = new StaticKeyProvider(options.signingKeyHex);
    this.adapterDid = options.adapterDid || keyProvider.getDid();
    this.keyId = options.signingKeyId ?? 'epc-adapter';
    this.signer = new VcSigner(keyProvider, this.keyId, this.adapterDid);
    this.statusListBaseUrl = options.statusListBaseUrl ?? `https://adapters.propdata.org.uk/status/epc`;
  }

  /**
   * Build and sign a PDTF PropertyCredential from an EPC record.
   * Conforms to Sub-spec 02 §3.2 and §11.1.
   */
  async buildCredential(record: EpcRecord, _rawBody: string): Promise<Record<string, unknown>> {
    const lmkKey = record['lmk-key'];
    const uprn = record.uprn;
    const retrievedAt = new Date().toISOString();

    // EPCs are valid for 10 years from lodgement
    const expiryDate = computeExpiryDate(record['lodgement-date']);
    const lodgementDatetime = record['lodgement-datetime'] || record['lodgement-date'];

    // Allocate a status list index (in production this comes from a proper allocator)
    const statusIndex = String(this.statusListIndex++);
    const statusListId = `${this.statusListBaseUrl}/list-001`;

    const vc = await this.signer.sign({
      id: `urn:pdtf:vc:epc-${randomUUID()}`,
      type: 'PropertyCredential',
      validFrom: retrievedAt,
      validUntil: `${expiryDate}T00:00:00Z`,
      credentialSubject: {
        id: `urn:pdtf:uprn:${uprn}`,
        energyEfficiency: {
          certificate: {
            certificateNumber: lmkKey,
            currentEnergyRating: record['current-energy-rating'],
            currentEnergyEfficiency: parseNum(record['current-energy-efficiency']),
            potentialEnergyRating: record['potential-energy-rating'],
            potentialEnergyEfficiency: parseNum(record['potential-energy-efficiency']),
            environmentalImpactCurrent: parseNum(record['environment-impact-current']),
            environmentalImpactPotential: parseNum(record['environment-impact-potential']),
            energyConsumptionCurrent: parseNum(record['energy-consumption-current']),
            energyConsumptionPotential: parseNum(record['energy-consumption-potential']),
            co2EmissionsCurrent: parseNum(record['co2-emissions-current']),
            co2EmissionsPotential: parseNum(record['co2-emissions-potential']),
            co2EmissionsPerFloorArea: parseNum(record['co2-emiss-curr-per-floor-area']),
            lodgementDate: record['lodgement-date'],
            expiryDate,
            inspectionDate: record['inspection-date'],
            totalFloorArea: parseNum(record['total-floor-area']),
            propertyType: record['property-type'],
            builtForm: record['built-form'],
            wallsDescription: record['walls-description'] || undefined,
            roofDescription: record['roof-description'] || undefined,
            floorDescription: record['floor-description'] || undefined,
            windowsDescription: record['windows-description'] || undefined,
            mainHeatingDescription: record['main-heating-description'] || undefined,
            mainFuel: record['main-fuel'] || undefined,
            heatingCostCurrent: parseNum(record['heating-cost-current']),
            heatingCostPotential: parseNum(record['heating-cost-potential']),
            hotWaterCostCurrent: parseNum(record['hot-water-cost-current']),
            hotWaterCostPotential: parseNum(record['hot-water-cost-potential']),
            lightingCostCurrent: parseNum(record['lighting-cost-current']),
            lightingCostPotential: parseNum(record['lighting-cost-potential']),
          },
        },
      },
      evidence: [
        {
          type: 'ElectronicRecord',
          source: 'epc.opendatacommunities.org',
          retrievedAt,
          method: 'API',
        },
      ],
      termsOfUse: [
        {
          type: 'PdtfAccessPolicy',
          confidentiality: 'public',
        },
      ],
      credentialStatus: {
        id: `${statusListId}#${statusIndex}`,
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: statusIndex,
        statusListCredential: statusListId,
      },
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

function computeExpiryDate(lodgementDate: string): string {
  const d = new Date(lodgementDate);
  d.setFullYear(d.getFullYear() + 10);
  return d.toISOString().split('T')[0];
}
