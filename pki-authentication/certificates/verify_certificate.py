from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
from pathlib import Path


CA_DIR = Path("ca/certificates")
CERT_DIR = Path("certificates/issued")


# --------------------------------------------------
# 1. Load CA certificate
# --------------------------------------------------

with open(CA_DIR / "ca_certificate.pem", "rb") as f:
    ca_certificate = x509.load_pem_x509_certificate(
        f.read()
    )


# --------------------------------------------------
# 2. Load caller certificate
# --------------------------------------------------

with open(CERT_DIR / "aryan_certificate.pem", "rb") as f:
    caller_certificate = x509.load_pem_x509_certificate(
        f.read()
    )


print("Certificates loaded successfully.")


# --------------------------------------------------
# 3. Check the issuer
# --------------------------------------------------

if caller_certificate.issuer != ca_certificate.subject:
    print("❌ Certificate issuer does not match our CA.")
    exit()

print("✓ Certificate issuer matches our CA.")


# --------------------------------------------------
# 4. Verify CA signature
# --------------------------------------------------

ca_public_key = ca_certificate.public_key()

try:

    ca_public_key.verify(
        caller_certificate.signature,
        caller_certificate.tbs_certificate_bytes,
        ec.ECDSA(caller_certificate.signature_hash_algorithm)
    )

    print("✓ Certificate signature is valid.")

except InvalidSignature:

    print("❌ Certificate signature is INVALID.")
    exit()


# --------------------------------------------------
# 5. Check certificate validity dates
# --------------------------------------------------

current_time = datetime.now(timezone.utc)

not_before = caller_certificate.not_valid_before_utc
not_after = caller_certificate.not_valid_after_utc


if current_time < not_before:

    print("❌ Certificate is not valid yet.")
    exit()


if current_time > not_after:

    print("❌ Certificate has expired.")
    exit()


print("✓ Certificate is within its validity period.")


# --------------------------------------------------
# 6. Read caller identity
# --------------------------------------------------

common_name = caller_certificate.subject.get_attributes_for_oid(
    x509.NameOID.COMMON_NAME
)[0].value


print()
print("Certificate identity:", common_name)
print("Certificate serial:", caller_certificate.serial_number)


# --------------------------------------------------
# Final result
# --------------------------------------------------

print()

print("CERTIFICATE VERIFIED ✓")
