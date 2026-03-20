# Tutorial: Broken First, Then Hardened

This tutorial shows the same demo image in two states:

- first as a basic container image with weak supply-chain evidence
- then as a hardened image with signing, provenance, Scorecard, and advisory data that Otter can display

Use the sample app in [examples/supply-chain-demo](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo).

## Goal

Show why these sections may be empty in Otter:

- OpenSSF Scorecard
- SLSA / provenance
- Attestations
- Advisories and VEX

Then show what changes are needed so those sections start working.

## Part 1: Baseline image

### What to do

1. Put the sample app in a public GitHub repository or keep it local.
2. Build and push the image without signing or provenance.
3. Scan it in Otter.

Example insecure publish workflow:

- [container-insecure.yml.example](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/workflows/container-insecure.yml.example)

### What Otter will likely show

- Vulnerabilities: works
- SBOM: works
- Tags: works if the tag is scanned or the registry allows listing
- Attestations: `0`
- Provenance: `0`
- SLSA builder / build type / invocation: unavailable
- Scorecard: unavailable or missing GitHub source evidence
- Advisory overlays: none

### Why it looks incomplete

Otter is not inventing those sections. It only shows what it can discover from the image, registry referrers, provenance metadata, and imported advisories.

If you only push a plain image:

- there may be no OCI referrers
- there may be no cosign signature
- there may be no provenance attestation
- there may be no GitHub repository evidence for Scorecard
- there may be no OpenVEX data

## Part 2: Hardened image

### What to change

1. Publish the image to GHCR with a repository name that maps cleanly to the public GitHub repo.
2. Sign the image with Cosign.
3. Publish build provenance using GitHub's build provenance attestation action.
4. Enable Scorecard on the repository.
5. Import an OpenVEX document into Otter.

Example hardened publish workflow:

- [container-hardened.yml.example](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/workflows/container-hardened.yml.example)

Example Scorecard workflow:

- [scorecard.yml.example](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/workflows/scorecard.yml.example)

Example VEX document:

- [not-affected-openvex.json](/Users/rahulxf/personal-rahulxf/otter/examples/supply-chain-demo/vex/not-affected-openvex.json)

### What Otter should show now

- Attestations tab: signatures and attestation records
- Overview / Compliance:
  - builder
  - build type
  - invocation
  - higher SLSA posture
- Scorecard:
  - available if Otter can infer the public GitHub repo
- Advisories:
  - VEX document listed
  - advisory-backed vulnerability status updated

## How to get each section working

## Scorecard

For Otter to show Scorecard:

- the repository must be public on GitHub
- Otter must be able to infer the GitHub repo from provenance materials or image naming
- GHCR naming should map cleanly to the repo, for example `ghcr.io/<owner>/<repo>`
- the repo should run the Scorecard workflow and publish results

If Otter says `no GitHub source repository evidence found`, the usual fixes are:

- publish provenance with source materials
- use a public GitHub repo
- keep the image naming aligned with the repo

## SLSA and provenance

For Otter to show builder, build type, and invocation:

- publish provenance with `actions/attest-build-provenance`
- use GitHub Actions OIDC permissions
- push the image to a registry that preserves OCI referrers

Otter derives SLSA posture from the discovered provenance record. If those fields are missing from the attestation, Otter cannot display them.

## Attestations and signatures

For Otter to show attestation coverage:

- sign the image with Cosign
- publish provenance or other attestations
- make sure the registry exposes OCI referrers for that image

If the registry or image has no referrers, Otter will correctly show zeros.

## Advisories and VEX

Otter supports advisory overlays through OpenVEX import.

Example:

```bash
curl -X POST "http://localhost:7789/api/v1/images/<image-id>/vex?org_id=default" \
  -F "file=@examples/supply-chain-demo/vex/not-affected-openvex.json"
```

After import:

- the VEX document appears in the Advisories tab
- matching vulnerabilities change status according to the VEX statement

## Recommended demo sequence

1. Publish the insecure image
2. Scan it in Otter
3. Capture the missing sections
4. Publish the hardened image
5. Scan it again in Otter
6. Import the sample OpenVEX document
7. Compare the before and after screenshots
