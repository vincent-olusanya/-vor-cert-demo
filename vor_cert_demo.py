#!/usr/bin/env python3
"""
VOR-CERT Demo — Public Reference Implementation
================================================

A minimal, public demonstration of the VOR-CERT epistemic claim-typing
standard for professional document integrity.

What this demo does:
  - Generates an Ed25519 issuer keypair
  - Binds a SHA-256 hash of a payload file to a manifest of typed claims
  - Signs the manifest canonically
  - Verifies signature, payload integrity, and claim type structure

What this demo deliberately does NOT do (production implementation only):
  - Dual-model adversarial audit reconciliation
  - Rekor transparency log anchoring
  - Hardened CI/CD pipeline with gated OIDC signing
  - Browser-based forensic verification portal with HISTORY_ALTERED detection
  - Revocation and supersession registry logic
  - External trust anchor for issuer identity (the demo trusts the manifest's
    embedded key — a real deployment binds identity via OIDC or X.509)

The honest disclosure of these gaps is itself part of the demonstration:
a verifiable document standard must be transparent about what it does
and does not establish.

Hardened production implementation available for evaluation under NDA.

Usage:
  python vor_cert_demo.py init --name "Your Name"
  python vor_cert_demo.py certify document.txt --title "My Document"
  python vor_cert_demo.py verify path/to/manifest.json --payload document.txt
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("ERROR: cryptography library required. Install with:")
    print("  pip install cryptography")
    sys.exit(1)

SPEC_VERSION = "demo-0.2"
CLAIM_TYPES = {"fact", "inference", "forecast", "opinion", "self_assessment"}
KEY_DIR = Path.home() / ".vor_cert_demo"
REGISTRY_DIR = Path("./vor_cert_registry")
IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9 ._\-]{1,64}$")


def sanitize_identity(name: str) -> str:
    """Reject identities containing path separators or control characters."""
    if not IDENTITY_PATTERN.match(name):
        raise ValueError(
            "Identity must be 1-64 chars, only letters, digits, spaces, "
            "dots, underscores, and hyphens allowed."
        )
    return name


def canonical_json(obj) -> bytes:
    """Deterministic JSON encoding for signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def cmd_init(args):
    """Generate a new issuer keypair."""
    try:
        identity = sanitize_identity(args.name)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    KEY_DIR.mkdir(exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (KEY_DIR / "private.pem").write_bytes(private_bytes)
    (KEY_DIR / "public.pem").write_bytes(public_bytes)
    (KEY_DIR / "identity.txt").write_text(identity)

    os.chmod(KEY_DIR / "private.pem", 0o600)

    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    print(f"Issuer keypair generated for: {identity}")
    print(f"Keys stored in: {KEY_DIR}")
    print(f"Public key fingerprint (full SHA-256): {fingerprint}")
    print()
    print("NOTE: This is a demo. In a real deployment, the issuer identity")
    print("would be bound to an external trust anchor (OIDC, X.509, or")
    print("transparency log) rather than self-asserted.")


def cmd_certify(args):
    """Certify a document with typed claims."""
    if not (KEY_DIR / "private.pem").exists():
        print("ERROR: Run 'init' first to generate issuer keys.")
        sys.exit(1)

    payload_path = Path(args.file)
    if not payload_path.exists():
        print(f"ERROR: File not found: {payload_path}")
        sys.exit(1)

    payload_bytes = payload_path.read_bytes()
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    identity = (KEY_DIR / "identity.txt").read_text().strip()
    public_bytes = (KEY_DIR / "public.pem").read_bytes()

    print("\nEnter claims (one per line, format: TYPE: claim text)")
    print(f"Valid types: {', '.join(sorted(CLAIM_TYPES))}")
    print("Blank line to finish.\n")

    claims = []
    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            break
        if not line:
            break
        if ":" not in line:
            print("  Skipped: missing colon separator")
            continue
        claim_type, claim_text = line.split(":", 1)
        claim_type = claim_type.strip().lower()
        claim_text = claim_text.strip()
        if claim_type not in CLAIM_TYPES:
            print(f"  Skipped: '{claim_type}' not a valid type")
            continue
        if not claim_text:
            print("  Skipped: empty claim text")
            continue
        claims.append({"type": claim_type, "text": claim_text})

    if not claims:
        print("ERROR: At least one claim required.")
        sys.exit(1)

    artifact_id = (
        f"VRC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{payload_hash[:8]}"
    )

    # The signed body — everything cryptographically bound to the signature.
    # Mutable state (transparency log anchoring) is kept OUTSIDE this block
    # so it can be updated post-signing without invalidating the signature.
    signed_body = {
        "spec_version": SPEC_VERSION,
        "artifact_id": artifact_id,
        "title": args.title,
        "issuer": {
            "identity": identity,
            "public_key_pem": public_bytes.decode(),
            "fingerprint_sha256": hashlib.sha256(public_bytes).hexdigest(),
        },
        "payload": {
            "filename": payload_path.name,
            "sha256": payload_hash,
            "size_bytes": len(payload_bytes),
        },
        "claims": claims,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    private_bytes = (KEY_DIR / "private.pem").read_bytes()
    private_key = serialization.load_pem_private_key(private_bytes, password=None)
    signature = private_key.sign(canonical_json(signed_body))

    sealed = {
        "signed_body": signed_body,
        "signature_hex": signature.hex(),
        # Transparency log state lives outside signed_body — mutable.
        "transparency_log": {
            "status": "not_anchored",
            "note": "Production implementation anchors to Rekor transparency log.",
        },
    }

    REGISTRY_DIR.mkdir(exist_ok=True)
    output_path = REGISTRY_DIR / f"{artifact_id}.json"
    output_path.write_text(json.dumps(sealed, indent=2))

    print(f"\n{'=' * 60}")
    print("VOR-CERT ARTIFACT SEAL  (demo)")
    print(f"{'=' * 60}")
    print(f"ID:        {artifact_id}")
    print(f"PAYLOAD:   {payload_hash}")
    print(f"CLAIMS:    {len(claims)} typed")
    for c in claims:
        print(f"  [{c['type']:>15}] {c['text'][:60]}")
    print(f"SIGNED:    Yes (Ed25519)")
    print(f"ANCHORED:  No (demo limitation)")
    print(f"MANIFEST:  {output_path}")
    print(f"{'=' * 60}")


def cmd_verify(args):
    """Verify a signed manifest. Payload file path may be provided explicitly."""
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: Manifest not found: {manifest_path}")
        sys.exit(1)

    try:
        sealed = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: Manifest is not valid JSON: {e}")
        sys.exit(1)

    # Schema validation
    required_top = {"signed_body", "signature_hex", "transparency_log"}
    missing = required_top - set(sealed.keys())
    if missing:
        print(f"ERROR: Manifest missing required keys: {sorted(missing)}")
        sys.exit(1)

    signed_body = sealed["signed_body"]
    required_body = {
        "spec_version", "artifact_id", "title", "issuer",
        "payload", "claims", "issued_at",
    }
    missing_body = required_body - set(signed_body.keys())
    if missing_body:
        print(f"ERROR: signed_body missing required keys: {sorted(missing_body)}")
        sys.exit(1)

    if signed_body["spec_version"] != SPEC_VERSION:
        print(
            f"WARNING: Manifest spec version is {signed_body['spec_version']}, "
            f"this tool implements {SPEC_VERSION}. Verification may be incomplete."
        )

    try:
        signature_bytes = bytes.fromhex(sealed["signature_hex"])
    except ValueError:
        print("ERROR: signature_hex is not valid hex")
        sys.exit(1)

    print(f"\nVerifying: {signed_body['artifact_id']}")
    print(f"Title:     {signed_body['title']}")
    print(f"Issuer:    {signed_body['issuer'].get('identity', '<unknown>')}")
    print(f"Issued:    {signed_body['issued_at']}")
    print()

    checks = []  # list of (description, status: True/False/None)

    # Check 1: Signature
    try:
        public_key = serialization.load_pem_public_key(
            signed_body["issuer"]["public_key_pem"].encode()
        )
        public_key.verify(signature_bytes, canonical_json(signed_body))
        checks.append(("Signature valid (Ed25519)", True))
    except InvalidSignature:
        checks.append(("Signature INVALID — does not match signed body", False))
    except (ValueError, TypeError) as e:
        checks.append((f"Signature check error: {type(e).__name__}: {e}", False))

    # Check 2: Payload integrity — REQUIRES the payload file
    expected_hash = signed_body["payload"]["sha256"]
    payload_name = signed_body["payload"]["filename"]

    payload_file = None
    if args.payload:
        payload_file = Path(args.payload)
    else:
        # Try sibling of manifest directory
        candidate = manifest_path.parent.parent / payload_name
        if candidate.exists():
            payload_file = candidate

    if payload_file is None or not payload_file.exists():
        checks.append((
            f"Payload integrity UNVERIFIED — file '{payload_name}' not provided "
            f"(pass --payload to verify)",
            False,  # treated as failure — honesty over false-positive
        ))
    else:
        actual_hash = hashlib.sha256(payload_file.read_bytes()).hexdigest()
        if actual_hash == expected_hash:
            checks.append((f"Payload integrity verified ({payload_file.name})", True))
        else:
            checks.append((f"Payload HASH MISMATCH for {payload_file.name}", False))

    # Check 3: Claim typing structure
    claims = signed_body.get("claims", [])
    if not claims:
        checks.append(("No claims present in manifest", False))
    else:
        invalid = [c for c in claims if c.get("type") not in CLAIM_TYPES]
        if invalid:
            invalid_types = [c.get("type") for c in invalid]
            checks.append((f"Invalid claim types found: {invalid_types}", False))
        else:
            checks.append(
                (f"Claim typing valid ({len(claims)} claims, all typed)", True)
            )

    # Check 4: Transparency log (mutable, lives outside signed_body)
    log_status = sealed["transparency_log"].get("status", "unknown")
    if log_status == "anchored":
        checks.append(("Transparency log anchored", True))
    else:
        checks.append(
            (f"Transparency log NOT anchored (status: {log_status}) — demo limitation",
             None)
        )

    print("Verification results:")
    for description, status in checks:
        if status is True:
            marker = "[OK]   "
        elif status is False:
            marker = "[FAIL] "
        else:
            marker = "[WARN] "
        print(f"  {marker}{description}")

    print()
    failed = [d for d, s in checks if s is False]
    warned = [d for d, s in checks if s is None]

    if failed:
        print("RESULT: FAILED — one or more critical verification checks did not pass.")
        sys.exit(2)
    elif warned:
        print("RESULT: PARTIAL — cryptographic checks passed, but limitations apply.")
        print("This demo does not establish:")
        print("  - That the issuer's identity is bound to an external trust anchor")
        print("  - That the manifest cannot be replaced via history rewriting")
        print("    (production: Rekor transparency log)")
        sys.exit(0)
    else:
        print("RESULT: VERIFIED — all checks passed within demo scope.")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="VOR-CERT Demo — Public Reference Implementation",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Generate issuer keypair")
    p_init.add_argument("--name", required=True, help="Issuer identity (1-64 chars)")
    p_init.set_defaults(func=cmd_init)

    p_cert = sub.add_parser("certify", help="Certify a document")
    p_cert.add_argument("file", help="File to certify")
    p_cert.add_argument("--title", required=True, help="Document title")
    p_cert.set_defaults(func=cmd_certify)

    p_ver = sub.add_parser("verify", help="Verify a signed manifest")
    p_ver.add_argument("manifest", help="Path to manifest JSON")
    p_ver.add_argument(
        "--payload",
        help="Path to the payload file (required to verify payload integrity)",
    )
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
