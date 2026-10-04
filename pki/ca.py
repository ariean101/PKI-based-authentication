from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from datetime import datetime, timedelta, timezone
from pathlib import Path


CA_DIRECTORY = Path("certificates/ca")

CA_PRIVATE_KEY_PATH = CA_DIRECTORY / "ca_private_key.pem"
CA_CERTIFICATE_PATH = CA_DIRECTORY / "ca_certificate.pem"


def create_private_ca():

    # Make sure CA directory exists
    CA_DIRECTORY.mkdir(parents=True, exist_ok=True)

    # Do not accidentally create another CA
    if CA_PRIVATE_KEY_PATH.exists() or CA_CERTIFICATE_PATH.exists():
        print("Private CA already exists.")
        return

    print("Creating Private CA...")


    # ------------------------------------------------
    # 1. Generate CA private key
    # ------------------------------------------------

    ca_private_key = ec.generate_private_key(
        ec.SECP256R1()
    )


    # ------------------------------------------------
    # 2. Define CA identity
    # ------------------------------------------------

    ca_name = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "PKI Call Authentication Root CA"
        ),

        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "PKI Call Authentication Project"
        )
    ])


    # ------------------------------------------------
    # 3. Create self-signed CA certificate
    # ------------------------------------------------

    now = datetime.now(timezone.utc)

    ca_certificate = (
        x509.CertificateBuilder()

        .subject_name(ca_name)

        # Root CA is self-signed
        .issuer_name(ca_name)

        .public_key(
            ca_private_key.public_key()
        )

        .serial_number(
            x509.random_serial_number()
        )

        .not_valid_before(now)

        .not_valid_after(
            now + timedelta(days=3650)
        )

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


    # ------------------------------------------------
    # 4. Save CA private key
    # ------------------------------------------------

    with open(CA_PRIVATE_KEY_PATH, "wb") as file:

        file.write(
            ca_private_key.private_bytes(

                encoding=serialization.Encoding.PEM,

                format=serialization.PrivateFormat.PKCS8,

                encryption_algorithm=serialization.NoEncryption()
            )
        )


    # ------------------------------------------------
    # 5. Save CA certificate
    # ------------------------------------------------

    with open(CA_CERTIFICATE_PATH, "wb") as file:

        file.write(
            ca_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )


    print("Private CA created successfully.")
    print(f"Private key: {CA_PRIVATE_KEY_PATH}")
    print(f"Certificate: {CA_CERTIFICATE_PATH}")


if __name__ == "__main__":
    create_private_ca()