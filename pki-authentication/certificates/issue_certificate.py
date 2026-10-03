from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone
from pathlib import Path


CA_DIR = Path("ca/certificates")
CERT_DIR = Path("certificates/issued")

CERT_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# 1. Load our CA private key
# --------------------------------------------------

with open(CA_DIR / "ca_private_key.pem", "rb") as f:
    ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )


# --------------------------------------------------
# 2. Load our CA certificate
# --------------------------------------------------

with open(CA_DIR / "ca_certificate.pem", "rb") as f:
    ca_certificate = x509.load_pem_x509_certificate(
        f.read()
    )


print("CA loaded successfully.")


# --------------------------------------------------
# 3. Create caller identity
# --------------------------------------------------

caller_name = "Aryan"


# --------------------------------------------------
# 4. Generate caller's private key
# --------------------------------------------------


caller_private_key = ec.generate_private_key(
    ec.SECP256R1()
)

caller_public_key = caller_private_key.public_key()

print("Caller key pair generated.")


# --------------------------------------------------
# 5. Create caller certificate
# --------------------------------------------------

caller_identity = x509.Name([
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        caller_name
    )
])


now = datetime.now(timezone.utc)

caller_certificate = (
    x509.CertificateBuilder()

    # Who owns this certificate?
    .subject_name(caller_identity)

    # Who issued this certificate?
    .issuer_name(ca_certificate.subject)

    # Caller public key
    .public_key(caller_public_key)

    # Unique certificate number
    .serial_number(x509.random_serial_number())

    # Certificate validity
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=365))

    # This is NOT a CA certificate
    .add_extension(
        x509.BasicConstraints(
            ca=False,
            path_length=None
        ),
        critical=True
    )

    # Sign using CA private key
    .sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256()
    )
)


print("Caller certificate created.")


# --------------------------------------------------
# 6. Save caller private key
# --------------------------------------------------

with open(CERT_DIR / "aryan_private_key.pem", "wb") as f:
    f.write(
        caller_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


# --------------------------------------------------
# 7. Save caller certificate
# --------------------------------------------------

with open(CERT_DIR / "aryan_certificate.pem", "wb") as f:
    f.write(
        caller_certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )


print("Caller files saved.")
print()
print("Identity:", caller_name)
print("Serial Number:", caller_certificate.serial_number)
print("Issuer:", caller_certificate.issuer)