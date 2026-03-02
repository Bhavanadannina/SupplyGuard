import hashlib
import os


def compute_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def generate_sbom_hash(sbom_path="sbom.json", hash_path="sbom.hash"):

    if not os.path.exists(sbom_path):
        print("[!] SBOM file not found. Cannot generate hash.")
        return None

    hash_value = compute_sha256(sbom_path)

    with open(hash_path, "w") as f:
        f.write(hash_value)

    print("🔐 SBOM SHA-256 Hash Generated")
    print(f"   Hash: {hash_value}")

    return hash_value

def verify_sbom_integrity(sbom_path="sbom.json", hash_path="sbom.hash"):

    if not os.path.exists(sbom_path):
        print("[!] SBOM file not found. Cannot verify integrity.")
        return False

    if not os.path.exists(hash_path):
        print("[!] No stored SBOM hash found. Skipping verification.")
        return True  # First run allowed

    current_hash = compute_sha256(sbom_path)

    with open(hash_path, "r") as f:
        stored_hash = f.read().strip()

    print("🔎 Verifying SBOM Integrity...")

    if current_hash == stored_hash:
        print("✅ SBOM Integrity Verified (No tampering detected)")
        return True
    else:
        print("❌ SBOM Integrity FAILED (SBOM has been modified)")
        print(f"   Stored Hash : {stored_hash}")
        print(f"   Current Hash: {current_hash}")
        return False