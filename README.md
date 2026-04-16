# @pdtf/epc-adapter

PDTF 2.0 EPC Adapter — an **OID4VCI credential issuer** and **OpenID Federation leaf entity** that fetches domestic Energy Performance Certificate data from the [UK EPC Register](https://epc.opendatacommunities.org/) and issues signed [PropertyCredentials](https://www.w3.org/TR/vc-data-model-2.0/) via [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

The adapter:
- Fetches EPC data from the government EPC Register API
- Issues signed PropertyCredentials via OID4VCI
- Publishes a federation entity configuration at `/.well-known/openid-federation`
- Holds a `property-data-provider` trust mark from the PDTF Trust Anchor

## How it works

```
UPRN or LMK key
      │
      ▼
  EPC Register API ──► Raw EPC data ──► Credential Builder ──► Signed VC
      │                                       │                     │
      │                                       ├─ SHA-256 evidence   │
      │                                       └─ Ed25519 signature  │
      ▼                                                             ▼
  epc.opendatacommunities.org                           PDTF Verifiable Credential
```

The adapter:
1. Fetches EPC data from the register by UPRN or LMK key
2. Maps the response into a structured PDTF credential subject (rating, property, address, fabric, heating, environment, costs)
3. Includes evidence (SHA-256 hash of the raw API response + fetch timestamp)
4. Signs the credential with Ed25519 using `eddsa-jcs-2022` via `@pdtf/core`

## Quick start

```bash
git clone https://github.com/property-data-standards-co/epc-adapter
cd epc-adapter
npm install
cp .env.example .env
# Edit .env with your EPC API credentials and signing key
npm run dev
```

### Generate a signing key

```bash
npx @pdtf/core keygen
# or:
node -e "const {ed25519} = require('@noble/curves/ed25519'); const k = ed25519.utils.randomPrivateKey(); console.log(Buffer.from(k).toString('hex'))"
```

### Register for the EPC API

1. Go to https://epc.opendatacommunities.org/
2. Create an account
3. Your email + API key go in `.env`

## API

### Issue credential by UPRN

```bash
curl -X POST http://localhost:8081/v1/credential/uprn/100023336956
```

### Issue credential by LMK key

```bash
curl -X POST http://localhost:8081/v1/credential/lmk/219873319402019053122194154717408
```

### Example response

The adapter produces a **PropertyCredential** per [PDTF Sub-spec 02 §3.2](https://property-data-standards-co.github.io/webv2/docs/specs/02-vc-data-model/). EPC data is represented under `energyEfficiency.certificate` on the Property entity — not a custom credential type (per D4: property-level VCs, not first-class entity VCs).

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://propdata.org.uk/credentials/v2"
  ],
  "type": ["VerifiableCredential", "PropertyCredential"],
  "id": "urn:pdtf:vc:epc-7f3a2b1c-9d4e-5f6a-8b7c-0d1e2f3a4b5c",
  "issuer": "did:key:z6Mk...",
  "validFrom": "2026-04-03T08:30:00Z",
  "validUntil": "2034-11-20T00:00:00Z",
  "credentialSubject": {
    "id": "urn:pdtf:uprn:100023336956",
    "energyEfficiency": {
      "certificate": {
        "certificateNumber": "0000-0000-0000-0000-0000",
        "currentEnergyRating": "D",
        "currentEnergyEfficiency": 64,
        "potentialEnergyRating": "B",
        "potentialEnergyEfficiency": 86,
        "environmentalImpactCurrent": 58,
        "environmentalImpactPotential": 82,
        "energyConsumptionCurrent": 215,
        "energyConsumptionPotential": 92,
        "co2EmissionsCurrent": 4.2,
        "co2EmissionsPotential": 1.8,
        "co2EmissionsPerFloorArea": 29,
        "lodgementDate": "2024-11-20",
        "expiryDate": "2034-11-20",
        "inspectionDate": "2024-11-15",
        "totalFloorArea": 145,
        "propertyType": "House",
        "builtForm": "Mid-Terrace",
        "wallsDescription": "Sandstone or limestone, as built, no insulation (assumed)",
        "roofDescription": "Pitched, 250 mm loft insulation",
        "floorDescription": "Solid, no insulation (assumed)",
        "windowsDescription": "Fully double glazed",
        "mainHeatingDescription": "Boiler and radiators, mains gas",
        "mainFuel": "mains gas",
        "heatingCostCurrent": 1240,
        "heatingCostPotential": 690,
        "hotWaterCostCurrent": 210,
        "hotWaterCostPotential": 140,
        "lightingCostCurrent": 132,
        "lightingCostPotential": 58
      }
    }
  },
  "evidence": [{
    "type": "ElectronicRecord",
    "source": "epc.opendatacommunities.org",
    "retrievedAt": "2026-04-03T08:30:00Z",
    "method": "API"
  }],
  "termsOfUse": [{
    "type": "PdtfAccessPolicy",
    "confidentiality": "public"
  }],
  "credentialStatus": {
    "id": "https://adapters.propdata.org.uk/status/epc/list-001#0",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "0",
    "statusListCredential": "https://adapters.propdata.org.uk/status/epc/list-001"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk...#z6Mk...",
    "proofPurpose": "assertionMethod",
    "created": "2026-04-03T08:30:00Z",
    "proofValue": "z..."
  }
}
```

### Health check

```bash
curl http://localhost:8081/v1/health
```

### DID document

```bash
curl http://localhost:8081/.well-known/did.json
```

## Verify a credential

Feed the output into the PDTF validation service:

```bash
curl -X POST http://localhost:8081/v1/credential/uprn/100023336956 \
  | curl -X POST https://validate.propdata.org.uk/v1/verify \
    -H "Content-Type: application/json" -d @-
```

Or verify locally with `@pdtf/core`:

```bash
npx @pdtf/core vc-verify ./epc-credential.json
```

## Docker

```bash
docker build -t epc-adapter .
docker run -p 8081:8081 --env-file .env epc-adapter
```

## Architecture

The adapter is an **OpenID Federation leaf entity** in the PDTF trust model — it fetches from a primary source (the EPC Register) and wraps the data in a signed credential issued via OID4VCI. It is registered with the [PDTF Trust Anchor](https://registry.propdata.org.uk) and holds a `property-data-provider` trust mark for these authorised entity:path combinations:

- `Property:/energyEfficiency/certificate`
- `Property:/energyEfficiency/rating`
- `Property:/energyEfficiency/environment`
- `Property:/energyEfficiency/costs`
- `Property:/energyEfficiency/fabric`
- `Property:/energyEfficiency/heating`

Trust is established through OpenID Federation: the adapter publishes its entity configuration at `/.well-known/openid-federation`, and relying parties resolve the trust chain back to the Trust Anchor at `registry.propdata.org.uk`.

## Tests

```bash
npm test
```

22 tests covering:
- EPC API client (auth, search, errors, retries)
- Credential builder (mapping, signing, evidence, edge cases)
- Server (endpoints, validation, error handling)

## License

MIT
