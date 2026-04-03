import { describe, it, expect } from 'vitest';
import { EpcCredentialBuilder } from '../credential-builder.js';
import { verifyProof } from '@pdtf/core';
import type { EpcRecord } from '../epc-client.js';
import mockResponse from '../../mocks/epc-response.json' with { type: 'json' };

// 64 hex chars = 32 bytes
const TEST_SECRET_HEX = 'abababababababababababababababababababababababababababababababab';

describe('EpcCredentialBuilder', () => {
  const builder = new EpcCredentialBuilder({ signingKeyHex: TEST_SECRET_HEX });

  it('derives adapter DID from signing key', () => {
    expect(builder.adapterDid).toMatch(/^did:key:z6Mk/);
  });

  it('produces a PropertyCredential per spec §3.2', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);

    // W3C VC v2 + PDTF v2 contexts
    expect((vc as any)['@context']).toContain('https://www.w3.org/ns/credentials/v2');
    expect((vc as any)['@context']).toContain('https://trust.propdata.org.uk/ns/pdtf/v2');

    // Type: PropertyCredential, not EnergyPerformanceCertificate
    expect((vc as any).type).toContain('VerifiableCredential');
    expect((vc as any).type).toContain('PropertyCredential');
    expect((vc as any).type).not.toContain('EnergyPerformanceCertificate');

    // Credential ID uses urn:pdtf:vc: format
    expect(vc.id).toMatch(/^urn:pdtf:vc:epc-/);

    // Issuer is the adapter DID
    expect(vc.issuer).toBe(builder.adapterDid);

    // validUntil = 10 years from lodgement
    expect(vc.validUntil).toBe('2034-11-20T00:00:00Z');
  });

  it('maps energyEfficiency.certificate paths per entity schema', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);
    const subject = (vc as any).credentialSubject;

    // Subject ID is urn:pdtf:uprn:{uprn}
    expect(subject.id).toBe('urn:pdtf:uprn:100023336956');

    // All data under energyEfficiency.certificate
    const cert = subject.energyEfficiency.certificate;
    expect(cert).toBeDefined();

    // Rating
    expect(cert.certificateNumber).toBe('0000-0000-0000-0000-0000');
    expect(cert.currentEnergyRating).toBe('D');
    expect(cert.currentEnergyEfficiency).toBe(64);
    expect(cert.potentialEnergyRating).toBe('B');
    expect(cert.potentialEnergyEfficiency).toBe(86);

    // Environmental impact
    expect(cert.environmentalImpactCurrent).toBe(58);
    expect(cert.environmentalImpactPotential).toBe(82);
    expect(cert.energyConsumptionCurrent).toBe(215);
    expect(cert.energyConsumptionPotential).toBe(92);

    // CO2
    expect(cert.co2EmissionsCurrent).toBe(4.2);
    expect(cert.co2EmissionsPotential).toBe(1.8);
    expect(cert.co2EmissionsPerFloorArea).toBe(29);

    // Dates
    expect(cert.lodgementDate).toBe('2024-11-20');
    expect(cert.expiryDate).toBe('2034-11-20');
    expect(cert.inspectionDate).toBe('2024-11-15');

    // Property details on the certificate
    expect(cert.totalFloorArea).toBe(145);
    expect(cert.propertyType).toBe('House');
    expect(cert.builtForm).toBe('Mid-Terrace');

    // Fabric
    expect(cert.wallsDescription).toContain('Sandstone');
    expect(cert.roofDescription).toContain('loft insulation');
    expect(cert.windowsDescription).toContain('double glazed');

    // Heating
    expect(cert.mainHeatingDescription).toContain('Boiler');
    expect(cert.mainFuel).toBe('mains gas');

    // Costs (numbers, not strings)
    expect(cert.heatingCostCurrent).toBe(1240);
    expect(cert.heatingCostPotential).toBe(690);
    expect(cert.lightingCostCurrent).toBe(132);
    expect(cert.lightingCostPotential).toBe(58);
  });

  it('includes spec-compliant evidence (ElectronicRecord)', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);
    const evidence = (vc as any).evidence;

    expect(evidence).toHaveLength(1);
    expect(evidence[0].type).toBe('ElectronicRecord');
    expect(evidence[0].source).toBe('epc.opendatacommunities.org');
    expect(evidence[0].retrievedAt).toBeDefined();
    expect(evidence[0].method).toBe('API');
  });

  it('includes termsOfUse (public)', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);
    const tou = (vc as any).termsOfUse;

    expect(tou).toHaveLength(1);
    expect(tou[0].type).toBe('PdtfAccessPolicy');
    expect(tou[0].confidentiality).toBe('public');
  });

  it('includes credentialStatus (BitstringStatusListEntry)', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);
    const status = (vc as any).credentialStatus;

    expect(status.type).toBe('BitstringStatusListEntry');
    expect(status.statusPurpose).toBe('revocation');
    expect(status.statusListIndex).toBeDefined();
    expect(status.statusListCredential).toContain('adapters.propdata.org.uk/status/epc');
    expect(status.id).toContain('#');
  });

  it('produces a verifiable DataIntegrityProof', async () => {
    const rawBody = JSON.stringify(mockResponse);
    const vc = await builder.buildCredential(mockResponse as unknown as EpcRecord, rawBody);

    const proof = (vc as any).proof;
    expect(proof.type).toBe('DataIntegrityProof');
    expect(proof.cryptosuite).toBe('eddsa-jcs-2022');
    expect(proof.proofPurpose).toBe('assertionMethod');
    expect(proof.verificationMethod).toContain(builder.adapterDid);

    // Verify the signature
    const { ed25519 } = await import('@noble/curves/ed25519');
    const secretBytes = hexToBytes(TEST_SECRET_HEX);
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
    const cert = (vc as any).credentialSubject.energyEfficiency.certificate;

    expect(cert.totalFloorArea).toBeUndefined();
    expect(cert.environmentalImpactCurrent).toBeUndefined();
    expect(cert.energyConsumptionCurrent).toBeUndefined();
  });
});

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
