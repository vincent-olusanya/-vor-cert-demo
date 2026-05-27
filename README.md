# VOR-CERT Demo

> A public reference implementation demonstrating the VOR-CERT epistemic claim-typing standard for professional document integrity.

This repository contains a **deliberately minimal** demonstration of the VOR-CERT standard. It shows the core mechanism — signed manifests binding cryptographically-typed claims to a payload hash — without exposing the hardened production architecture.

## What this demo shows

- Ed25519 keypair generation for issuer identity
- SHA-256 payload binding
- Mandatory epistemic claim typing (`fact`, `inference`, `forecast`, `opinion`, `self_assessment`)
- Cryptographic signing of canonical manifests (signed body separated from mutable state)
- Independent verification: signature, payload integrity, and claim structure
- Honest reporting of limitations (no false "verified" when verification is incomplete)

## What this demo does NOT include

The production implementation includes substantial additional capability not present in this public demo:

- **Dual-model adversarial audit reconciliation** — automated independent model evaluation of claims, with auto-promotion of disagreements to `disputed` status
- **Rekor transparency log anchoring** — public, append-only timestamp anchor that survives history rewriting
- **Hardened CI/CD pipeline** — gated signing via OIDC with manual approval, pinned action dependencies, key scrub on completion
- **Browser-based forensic verification portal** — drag-and-drop verification with `HISTORY_ALTERED` detection
- **Revocation and supersession** — registry-level lifecycle management with `superseded_by` chains
- **External trust anchor for issuer identity** — production binds identity via OIDC or X.509 rather than self-asserted public keys
- **Comparative analysis** — formal positioning against W3C VCs, C2PA, and Sigstore

These are available for review under NDA.

## Design choices worth noting

**The signed body is separated from mutable state.** The signature covers `signed_body` only. Fields like `transparency_log.status` live outside that block so they can be updated post-signing (e.g. when anchoring completes) without invalidating the signature.

**Verification fails honestly when payload is not provided.** A common bug in toy crypto tools is reporting "verified" when only the signature was checked. This demo refuses to claim verification of payload integrity unless the payload file is actually supplied (`--payload`).

**Schema validation runs before crypto.** A malformed manifest produces a clear error rather than a confusing crypto failure or KeyError.

**Identity inputs are sanitized.** The `init` command rejects identities containing path separators or control characters.

## Quick start

```bash
pip install cryptography

# Generate your issuer keypair
python vor_cert_demo.py init --name "Your Name"

# Certify a document
echo "This is a test document." > test.txt
python vor_cert_demo.py certify test.txt --title "Test Document"

# Enter claims when prompted, e.g.:
#   fact: This document was created on 2026-05-27
#   inference: The proposed architecture will reduce certification time
#   forecast: Adoption will accelerate as AI content proliferates
#   self_assessment: The methodology is rigorous

# Verify the resulting manifest (pass --payload to verify file integrity)
python vor_cert_demo.py verify vor_cert_registry/VRC-20260527-XXXXXXXX.json --payload test.txt
```

Replace `VRC-20260527-XXXXXXXX.json` with the actual filename printed during certification.

## Why claim typing matters

The core insight: in a world where AI-generated content is indistinguishable from accountable human writing, the crisis is epistemic, not technical. Existing document standards (W3C VCs, C2PA, Sigstore) prove **who** said **what**, when, and that it hasn't been altered. None of them requires the issuer to declare **what kind of claim** they're making.

VOR-CERT forces that declaration at the time of certification. A signed forecast cannot later be argued as a factual representation. An opinion cannot be retrofitted as analysis. The structure makes claim-type manipulation forensically visible.

## Verification result semantics

The verify command returns three possible outcomes:

- **VERIFIED** — all checks passed (signature, payload integrity, claim structure, transparency log anchoring)
- **PARTIAL** — cryptographic checks passed, but the demo cannot establish properties that require the production implementation (e.g. transparency log anchoring)
- **FAILED** — one or more critical checks did not pass (bad signature, payload tampering, missing payload, schema violation, invalid claim type)

Exit codes: `0` for VERIFIED or PARTIAL, `2` for FAILED, `1` for errors.

## License

This demo is released for evaluation purposes. The hardened implementation, comparative SOTA analysis, and deployment patterns are available under NDA.

## Contact

Open an issue or contact the issuer directly for evaluation access.
