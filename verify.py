import base64
import json
import os
import shutil
import subprocess
import urllib.request
from dotenv import load_dotenv

load_dotenv()

IMAGE = os.environ["IMAGE"]
REPO = os.environ["REPO"]
COSIGN_BIN = shutil.which("cosign") or "./cosign.exe"


def ensure_cosign():
    """Download cosign.exe if it's not installed on the system."""
    if not shutil.which("cosign") and not os.path.exists("cosign.exe"):
        print("Cosign not found in PATH. Downloading cosign.exe for Windows...")
        url = "https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe"
        urllib.request.urlretrieve(url, "cosign.exe")
        print("Download complete!")


# ---------------------------------------------------------
# 1. Detailed Image Signature & Certificate Verification
# ---------------------------------------------------------
def verify_image_signature(image: str, repo: str) -> tuple[bool, dict, str]:
    """Verifies image signature and extracts certificate/workflow metadata.
    Returns: (is_verified: bool, cert_info: dict, message: str)
    """
    ensure_cosign()
    cmd = [
        COSIGN_BIN,
        "verify",
        f"--certificate-identity-regexp=https://github.com/{repo}/*",
        "--certificate-oidc-issuer=https://token.actions.githubusercontent.com",
        "--output=json",
        image,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        signatures = json.loads(result.stdout)

        # Extract metadata from the verified signature payload
        optional_data = signatures[0].get("optional", {}) if signatures else {}

        cert_info = {
            "subject": optional_data.get("Subject") or optional_data.get("subject"),
            "issuer": optional_data.get("Issuer") or optional_data.get("issuer"),
            "workflow_trigger": optional_data.get("githubWorkflowTrigger"),
            "workflow_sha": optional_data.get("githubWorkflowSha"),
            "workflow_name": optional_data.get("githubWorkflowName"),
            "workflow_repository": optional_data.get("githubWorkflowRepository"),
            "workflow_ref": optional_data.get("githubWorkflowRef"),
        }

        return True, cert_info, "Image signature is VALID and VERIFIED."
    except subprocess.CalledProcessError as e:
        error_details = e.stderr.strip() if e.stderr else "Signature check failed."
        return False, {}, f"Image signature NOT VERIFIED: {error_details}"


# ---------------------------------------------------------
# Helper: Fetch Attestations (SLSA & SBOM)
# ---------------------------------------------------------
def get_attestation_payloads(image: str, repo: str, att_type: str) -> tuple[bool, list[dict], str]:
    ensure_cosign()
    cmd = [
        COSIGN_BIN,
        "verify-attestation",
        "--type",
        att_type,
        f"--certificate-identity-regexp=https://github.com/{repo}/*",
        "--certificate-oidc-issuer=https://token.actions.githubusercontent.com",
        image,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        error_details = e.stderr.strip() if e.stderr else "Attestation check failed."
        return False, [], f"Attestation NOT VERIFIED: {error_details}"

    statements = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue

        envelope = json.loads(line)
        if "payload" in envelope:
            decoded_bytes = base64.b64decode(envelope["payload"])
            statement = json.loads(decoded_bytes)
            statements.append(statement)

    return True, statements, "Attestation is VALID and VERIFIED."


# ---------------------------------------------------------
# 2. SLSA Provenance
# ---------------------------------------------------------
def verify_and_extract_slsa(image: str, repo: str) -> tuple[bool, str | None, str]:
    is_verified, statements, msg = get_attestation_payloads(image, repo, "slsaprovenance1")
    if not is_verified:
        return False, None, msg

    predicate = statements[0].get("predicate", {}) if statements else {}

    resolved_deps = (
        predicate.get("buildDefinition", {})
        .get("resolvedDependencies", [{}])[0]
        .get("digest", {})
    )
    if "gitCommit" in resolved_deps:
        return True, resolved_deps["gitCommit"], msg

    for mat in predicate.get("materials", []):
        digest = mat.get("digest", {})
        if "sha1" in digest:
            return True, digest["sha1"], msg

    config_digest = predicate.get("invocation", {}).get("configSource", {}).get("digest", {})
    return True, config_digest.get("sha1"), msg


# ---------------------------------------------------------
# 3. CycloneDX SBOM
# ---------------------------------------------------------
def verify_and_extract_sbom(image: str, repo: str) -> tuple[bool, list[dict], str]:
    is_verified, statements, msg = get_attestation_payloads(image, repo, "cyclonedx")
    if not is_verified:
        return False, [], msg

    predicate = statements[0].get("predicate", {}) if statements else {}
    raw_components = predicate.get("components", [])

    dependencies = [
        {
            "name": comp.get("name"),
            "version": comp.get("version"),
            "purl": comp.get("purl"),
            "type": comp.get("type"),
        }
        for comp in raw_components
    ]

    return True, dependencies, msg


# ---------------------------------------------------------
# Main Verification Execution & Print Report
# ---------------------------------------------------------
if __name__ == "__main__":
    print("==================================================")
    print(f"🔒 COSIGN VERIFICATION REPORT FOR: {IMAGE}")
    print("==================================================\n")

    # 1. Signature & Certificate Details
    sig_verified, cert_info, sig_msg = verify_image_signature(IMAGE, REPO)
    
    if sig_verified:
        print("✅ SIGNATURE STATUS: VERIFIED")
        print("The following checks were performed on each of these signatures:")
        print("  - The cosign claims were validated")
        print("  - Existence of the claims in the transparency log was verified offline")
        print("  - The code-signing certificate was verified using trusted certificate authority certificates\n")
        
        print("📜 Certificate & Workflow Claims:")
        print(f"  Certificate subject:            {cert_info.get('subject')}")
        print(f"  Certificate issuer URL:        {cert_info.get('issuer')}")
        print(f"  GitHub Workflow Trigger:       {cert_info.get('workflow_trigger')}")
        print(f"  GitHub Workflow SHA:           {cert_info.get('workflow_sha')}")
        print(f"  GitHub Workflow Name:          {cert_info.get('workflow_name')}")
        print(f"  GitHub Workflow Repository:    {cert_info.get('workflow_repository')}")
        print(f"  GitHub Workflow Ref:           {cert_info.get('workflow_ref')}\n")
    else:
        print("❌ SIGNATURE STATUS: NOT VERIFIED")
        print(f"   Detail: {sig_msg}\n")

    # 2. SLSA Provenance
    slsa_verified, commit_sha, slsa_msg = verify_and_extract_slsa(IMAGE, REPO)
    if slsa_verified:
        print("✅ SLSA PROVENANCE STATUS: VERIFIED")
        print(f"   Git Commit SHA: {commit_sha}\n")
    else:
        print("❌ SLSA PROVENANCE STATUS: NOT VERIFIED")
        print(f"   Detail: {slsa_msg}\n")

    # 3. SBOM Attestation
    sbom_verified, deps, sbom_msg = verify_and_extract_sbom(IMAGE, REPO)
    if sbom_verified:
        print("✅ SBOM ATTESTATION STATUS: VERIFIED")
        print(f"   Found {len(deps)} components in SBOM:")
        for dep in deps[:5]:
            print(f"   - {dep['name']} @ {dep['version']}")
        if len(deps) > 5:
            print(f"   ... and {len(deps) - 5} more.")
    else:
        print("❌ SBOM ATTESTATION STATUS: NOT VERIFIED")
        print(f"   Detail: {sbom_msg}")

    print("\n==================================================")