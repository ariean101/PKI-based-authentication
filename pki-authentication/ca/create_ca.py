from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
from pathlib import Path


# Folder where CA files will be stored
CA_DIR = Path("ca/certificates")
CA_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# 1. Generate the CA private key
# --------------------------------------------------

ca_private_key = ec.generate_private_key(
    ec.SECP256R1()
)

print("CA private key generated.")


# --------------------------------------------------
# 2. Define the identity of our CA
# --------------------------------------------------

ca_name = x509.Name([
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        "Project Root CA"
    ),
    x509.NameAttribute(
        NameOID.ORGANIZATION_NAME,
        "PKI Authentication Project"
    ),
])


# --------------------------------------------------
# 3. Create the CA certificate
# --------------------------------------------------

now = datetime.now(timezone.utc)

ca_certificate = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=3650))
    .add_extension(
        x509.BasicConstraints(
            ca=True,
            path_length=None
        ),
        critical=True
    )
    .sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256()
    )
)

print("CA certificate generated.")


# --------------------------------------------------
# 4. Save the CA private key
# --------------------------------------------------

with open(CA_DIR / "ca_private_key.pem", "wb") as f:
    f.write(
        ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


# --------------------------------------------------
# 5. Save the CA certificate
# --------------------------------------------------

with open(CA_DIR / "ca_certificate.pem", "wb") as f:
    f.write(
        ca_certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )


print("CA files saved successfully.")