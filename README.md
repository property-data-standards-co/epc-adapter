# @pdtf/epc-adapter

PDTF 2.0 EPC Adapter — fetches domestic Energy Performance Certificate data from the [UK EPC Register](https://epc.opendatacommunities.org/) and issues signed [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/).

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

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://propdata.org.uk/credentials/v2"
  ],
  "type": ["VerifiableCredential", "EnergyPerformanceCertificate"],
  "id": "urn:pdtf:epc:219873319402019053122194154717408",
  "issuer": "did:key:z6Mk...",
  "validFrom": "2024-11-20T09:45:12Z",
  "validUntil": "2034-11-20",
  "credentialSubject": {
    "id": "urn:pdtf:uprn:100023336956",
    "certificate": {
      "lmkKey": "219873319402019053122194154717408",
      "inspectionDate": "2024-11-15",
      "lodgementDate": "2024-11-20"
    },
    "rating": {
      "current": "D",
      "currentScore": 64,
      "potential": "B",
      "potentialScore": 86
    },
    "property": {
      "type": "House",
      "builtForm": "Mid-Terrace",
      "totalFloorArea": 145
    },
    "address": {
      "line1": "10 Downing Street",
      "line2": "Westminster",
      "postcode": "SW1A 2AA",
      "posttown": "London",
      "localAuthority": "Westminster",
      "constituency": "Cities of London and Westminster"
    },
    "fabric": {
      "walls": "Sandstone or limestone, as built, no insulation (assumed)",
      "roof": "Pitched, 250 mm loft insulation",
      "floor": "Solid, no insulation (assumed)",
      "windows": "Fully double glazed"
    },
    "heating": {
      "description": "Boiler and radiators, mains gas",
      "mainFuel": "mains gas"
    },
    "environment": {
      "co2Current": 4.2,
      "co2Potential": 1.8,
      "co2PerFloorArea": 29,
      "impactCurrent": 58,
      "impactPotential": 82,
      "energyConsumptionCurrent": 215,
      "energyConsumptionPotential": 92
    },
    "costs": {
      "heatingCurrent": 1240,
      "heatingPotential": 690,
      "hotWaterCurrent": 210,
      "hotWaterPotential": 140,
      "lightingCurrent": 132,
      "lightingPotential": 58
    }
  },
  "evidence": [{
    "type": "ElectronicRecord",
    "sourceUrl": "https://epc.opendatacommunities.org/api/v1/domestic/certificate/219873319402019053122194154717408",
    "fetchedAt": "2026-04-03T07:30:00Z",
    "sourceHash": "a1b2c3d4..."
  }],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk...#z6Mk...",
    "proofPurpose": "assertionMethod",
    "created": "2024-11-20T09:45:12Z",
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

The adapter is a **trusted proxy** in the PDTF trust model — it fetches from a primary source (the EPC Register) and wraps the data in a signed credential. It is registered in the [Trusted Issuer Registry](https://github.com/property-data-standards-co/tir) with authorised paths:

- `Property:/energyEfficiency/certificate`
- `Property:/energyEfficiency/rating`
- `Property:/energyEfficiency/environment`
- `Property:/energyEfficiency/costs`
- `Property:/energyEfficiency/fabric`
- `Property:/energyEfficiency/heating`

## Tests

```bash
npm test
```

20 tests covering:
- EPC API client (auth, search, errors, retries)
- Credential builder (mapping, signing, evidence, edge cases)
- Server (endpoints, validation, error handling)

## License

MIT
