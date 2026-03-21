# Tutorial: End-to-End Otter Supply Chain Walkthrough

This tutorial shows a complete flow:

1. write a small Go app
2. containerize it
3. publish it
4. sign it
5. attach build provenance
6. run Scorecard on the source repo
7. import a VEX advisory
8. analyze everything in Otter

The sample app lives in [examples/supply-chain-demo](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo).

## What this tutorial covers

- SBOM generation
- vulnerability scanning
- registry tags
- signatures
- provenance attestations
- SLSA-related fields
- Scorecard
- advisory and VEX overlays

## Prerequisites

- a public GitHub repository for the demo app
- GitHub Container Registry access
- GitHub Actions enabled
- Cosign keyless signing through GitHub OIDC
- Otter running locally

Run Otter locally:

```bash
OTTER_STORAGE=local go run .
```

Optional frontend:

```bash
cd frontend
npm install
npm run dev
```

## Step 1: Create the demo app

Use:

- [main.go](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/main.go)
- [go.mod](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/go.mod)

Build locally:

```bash
cd examples/supply-chain-demo
go build .
```

## Step 2: Containerize it

Use:

- [Dockerfile](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/Dockerfile)

Build locally:

```bash
docker build -t supply-chain-demo:local ./examples/supply-chain-demo
```

## Step 3: Publish the image

Push it to GHCR using the hardened workflow example:

- [container-hardened.yml.example](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/workflows/container-hardened.yml.example)

Recommended image name:

```text
ghcr.io/<owner>/supply-chain-demo:latest
```

That naming helps Otter infer the source repository when provenance is also present.

## Step 4: Sign the image

The hardened workflow runs:

```bash
cosign sign --yes ghcr.io/<owner>/supply-chain-demo@<digest>
```

This should make the Attestations tab show signature records once the registry referrers are discoverable.

## Step 5: Publish provenance

The hardened workflow also runs `actions/attest-build-provenance`.

That is the part that enables Otter to populate fields such as:

- Builder
- Build type
- Invocation
- Provenance count
- higher SLSA posture

Without provenance, those fields will stay unavailable.

## Step 6: Enable Scorecard

Add the Scorecard workflow:

- [scorecard.yml.example](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/workflows/scorecard.yml.example)

Important:

- the repo should be public
- the image should map back to the repo cleanly
- provenance materials should include GitHub source references when possible

If those are missing, Otter may still show:

```text
OpenSSF Scorecard unavailable
no GitHub source repository evidence found
```

## Step 7: Scan in Otter

From the UI:

1. open the directory page
2. enter `ghcr.io/<owner>/supply-chain-demo:latest`
3. queue the scan
4. wait for completion
5. open the image detail page

From the API:

```bash
curl -X POST http://localhost:7789/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "image_name": "ghcr.io/<owner>/supply-chain-demo:latest",
    "org_id": "default",
    "image_id": "supply-chain-demo",
    "async": true
  }'
```

## Step 8: Read the output in Otter

### Overview tab

Look for:

- registry and repository identity
- package count
- vulnerability summary
- scanner availability messages

### Vulnerabilities tab

Look for:

- merged Grype and Trivy results
- CVE detail drawer
- fix versions
- advisory state after VEX import

### SBOM tab

Look for:

- package inventory
- dependency tree
- artifact JSON viewer

### Attestations tab

Look for:

- signatures
- attestations
- provenance count
- signer and builder metadata

### Compliance tab

Look for:

- builder
- build type
- invocation
- Scorecard result
- standards summary

## Step 9: Import a VEX document

Use:

- [not-affected-openvex.json](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/vex/not-affected-openvex.json)

Import command:

```bash
curl -X POST "http://localhost:7789/api/v1/images/<image-id>/vex?org_id=default" \
  -F "file=@examples/supply-chain-demo/vex/not-affected-openvex.json"
```

What should change:

- VEX document appears in the Advisories tab
- the matching vulnerability status changes from `affected` to `not_affected`

## What still may not show up

Even with the hardened workflow, some sections can still remain sparse depending on the registry and repo setup.

### Scorecard still unavailable

Check:

- the repo is public
- Scorecard workflow ran successfully
- the image name maps to the repo
- provenance materials mention the GitHub source repo

### Attestations still zero

Check:

- Cosign signing completed successfully
- provenance attestation job completed successfully
- the registry preserves OCI referrers

### SLSA fields still unavailable

Check:

- provenance was actually published
- the attestation contains builder, build type, and invocation data

## Best demo outcome

If everything is wired correctly, Otter should show:

- a stored image with SBOM and vulnerabilities
- signatures and provenance in the Attestations tab
- builder and provenance-based posture in Compliance
- Scorecard for the public source repository
- VEX-driven status changes in Advisories
