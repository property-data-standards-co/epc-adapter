import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { EpcCredentialBuilder } from '../credential-builder.js';
import { verifyProof } from '@pdtf/core';
import type { EpcRecord } from '../epc-client.js';
import mockResponse from '../../mocks/epc-response.json' with { type: 'json' };

// Deterministic test key (same seed as cross-language vectors)
const TEST_SECRET_HEX = 'abababababababababababababababababababababababababababababababab';

describe('EpcCredentialBuilder', () => {
  const builder = new EpcCredentialBuilder({ signingKeyHex: TEST_SECRET_HEX });

  it('derives adapter DID from signing key', () => {
    expect(builder.adapterDid).toMatch(/^did:key:z6Mk/);
  });

  it('builds a valid VC structure', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);

    // W3C VC envelope
    expect((vc as any)['@context']).toContain('https://www.w3.org/ns/credentials/v2');
    expect((vc as any)['@context']).toContain('https://propdata.org.uk/credentials/v2');
    expect((vc as any).type).toContain('VerifiableCredential');
    expect((vc as any).type).toContain('EnergyPerformanceCertificate');

    // ID and issuer
    expect(vc.id).toBe('urn:pdtf:epc:0000-0000-0000-0000-0000');
    expect(vc.issuer).toBe(builder.adapterDid);

    // Validity
    expect(vc.validFrom).toBe('2024-11-20T09:45:12Z');
    expect(vc.validUntil).toBe('2034-11-20');
  });

  it('maps credential subject correctly', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);
    const subject = (vc as any).credentialSubject;

    expect(subject.id).toBe('urn:pdtf:uprn:100023336956');

    // Certificate info
    expect(subject.certificate.lmkKey).toBe('0000-0000-0000-0000-0000');
    expect(subject.certificate.inspectionDate).toBe('2024-11-15');
    expect(subject.certificate.lodgementDate).toBe('2024-11-20');

    // Rating
    expect(subject.rating.current).toBe('D');
    expect(subject.rating.currentScore).toBe(64);
    expect(subject.rating.potential).toBe('B');
    expect(subject.rating.potentialScore).toBe(86);

    // Property
    expect(subject.property.type).toBe('House');
    expect(subject.property.builtForm).toBe('Mid-Terrace');
    expect(subject.property.totalFloorArea).toBe(145);

    // Address
    expect(subject.address.line1).toBe('10 Downing Street');
    expect(subject.address.postcode).toBe('SW1A 2AA');
    expect(subject.address.localAuthority).toBe('Westminster');

    // Fabric
    expect(subject.fabric.walls).toContain('Sandstone');
    expect(subject.fabric.roof).toContain('loft insulation');
    expect(subject.fabric.windows).toContain('double glazed');

    // Heating
    expect(subject.heating.description).toContain('Boiler');
    expect(subject.heating.mainFuel).toBe('mains gas');

    // Environment
    expect(subject.environment.co2Current).toBe(4.2);
    expect(subject.environment.co2Potential).toBe(1.8);
    expect(subject.environment.co2PerFloorArea).toBe(29);

    // Costs (parsed as numbers)
    expect(subject.costs.heatingCurrent).toBe(1240);
    expect(subject.costs.lightingPotential).toBe(58);
  });

  it('includes evidence with source hash', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);
    const evidence = (vc as any).evidence;

    expect(evidence).toHaveLength(1);
    expect(evidence[0].type).toBe('ElectronicRecord');
    expect(evidence[0].sourceUrl).toContain('0000-0000-0000-0000-0000');
    expect(evidence[0].fetchedAt).toBeDefined();

    // Verify hash
    const expectedHash = createHash('sha256').update(rawBody).digest('hex');
    expect(evidence[0].sourceHash).toBe(expectedHash);
  });

  it('produces a verifiable DataIntegrityProof', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);

    // Check proof structure
    const proof = (vc as any).proof;
    expect(proof.type).toBe('DataIntegrityProof');
    expect(proof.cryptosuite).toBe('eddsa-jcs-2022');
    expect(proof.proofPurpose).toBe('assertionMethod');
    expect(proof.verificationMethod).toContain(builder.adapterDid);

    // Actually verify the signature
    // Need to get the public key from the builder's DID
    const { resolveDidKey: resolveDid } = await import('@pdtf/core');
    const didDoc = resolveDid(builder.adapterDid);
    // Re-derive the public key from the secret
    const { ed25519 } = await import('@noble/curves/ed25519');
    const secretBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      secretBytes[i] = parseInt(TEST_SECRET_HEX.substring(i * 2, i * 2 + 2), 16);
    }
    const publicKey = ed25519.getPublicKey(secretBytes);

    const valid = verifyProof({ document: vc as any, publicKey });
    expect(valid).toBe(true);
  });

  it('handles missing/invalid EPC fields gracefully', async () => {
    const sparse: Record<string, string> = {
      'lmk-key': 'sparse-key',
      uprn: '123',
      address1: 'Test',
      address2: '',
      address3: '',
      postcode: 'AB1 2CD',
      posttown: 'Test Town',
      'current-energy-rating': 'C',
      'current-energy-efficiency': '70',
      'potential-energy-rating': 'B',
      'potential-energy-efficiency': '85',
      'property-type': 'Flat',
      'built-form': 'Detached',
      'floor-description': '',
      'walls-description': '',
      'roof-description': '',
      'windows-description': '',
      'main-heating-description': '',
      'main-fuel': '',
      'total-floor-area': 'NO DATA!',
      'inspection-date': '2024-01-01',
      'lodgement-date': '2024-01-05',
      'lodgement-datetime': '2024-01-05T10:00:00Z',
      'environment-impact-current': 'INVALID!',
      'environment-impact-potential': '',
      'energy-consumption-current': 'N/A',
      'energy-consumption-potential': '',
      'co2-emissions-current': '',
      'co2-emiss-curr-per-floor-area': '',
      'co2-emissions-potential': '',
      'lighting-cost-current': '',
      'lighting-cost-potential': '',
      'heating-cost-current': '',
      'heating-cost-potential': '',
      'hot-water-cost-current': '',
      'hot-water-cost-potential': '',
      constituency: '',
      'local-authority': '',
      county: '',
    };
    const rawBody = JSON.stringify(sparse);
    const vc = await builder.buildCredential(sparse as unknown as EpcRecord, rawBody);
    const subject = (vc as any).credentialSubject;

    expect(subject.property.totalFloorArea).toBeUndefined();
    expect(subject.environment.impactCurrent).toBeUndefined();
    expect(subject.environment.energyConsumptionCurrent).toBeUndefined();
  });
});
