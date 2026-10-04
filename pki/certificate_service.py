from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from datetime import datetime, timedelta, timezone
from pathlib import Path

from pki.ca import (
    CA_PRIVATE_KEY_PATH,
    CA_CERTIFICATE_PATH
)


USER_CERTIFICATE_DIRECTORY = Path("certificates/users")


def issue_user_certificate(user_id: int, name: str, phone: str):

    # ------------------------------------------------
    # 1. Create directory for this user
    # ------------------------------------------------

    user_directory = USER_CERTIFICATE_DIRECTORY / str(user_id)

    user_directory.mkdir(
        parents=True,
        exist_ok=True
    )


    private_key_path = user_directory / "private_key.pem"
    csr_path = user_directory / "request.csr"
    certificate_path = user_directory / "certificate.pem"


    # ------------------------------------------------
    # 2. Generate user's EC private key
    # ------------------------------------------------

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()


    # ------------------------------------------------
    # 3. Save user's private key
    # ------------------------------------------------

    with open(private_key_path, "wb") as file:

        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )


    # ------------------------------------------------
    # 4. Generate Certificate Signing Request (CSR)
    # ------------------------------------------------

    subject = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            name
        ),

        x509.NameAttribute(
            NameOID.USER_ID,
            str(user_id)
        ),

        x509.NameAttribute(
            NameOID.SERIAL_NUMBER,
            phone
        )
    ])


    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(
            private_key,
            hashes.SHA256()
        )
    )


    # Save CSR
    with open(csr_path, "wb") as file:

        file.write(
            csr.public_bytes(
                serialization.Encoding.PEM
            )
        )


    # ------------------------------------------------
    # 5. Load Private CA
    # ------------------------------------------------

    with open(CA_PRIVATE_KEY_PATH, "rb") as file:

        ca_private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )


    with open(CA_CERTIFICATE_PATH, "rb") as file:

        ca_certificate = x509.load_pem_x509_certificate(
            file.read()
        )


    # ------------------------------------------------
    # 6. CA signs certificate
    # ------------------------------------------------

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()

        .subject_name(
            csr.subject
        )

        .issuer_name(
            ca_certificate.subject
        )

        .public_key(
            public_key
        )

        .serial_number(
            x509.random_serial_number()
        )

        .not_valid_before(
            now
        )

        .not_valid_after(
            now + timedelta(days=365)
        )

        .add_extension(
            x509.BasicConstraints(
                ca=False,
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
    # 7. Save issued certificate
    # ------------------------------------------------

    with open(certificate_path, "wb") as file:

        file.write(
            certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )


    # ------------------------------------------------
    # 8. Return certificate information
    # ------------------------------------------------

    return {
        "serial_number": str(certificate.serial_number),

        "certificate_path": str(certificate_path),

        "private_key_path": str(private_key_path),

        "csr_path": str(csr_path),

        "issued_at": now.isoformat(),

        "expires_at": (
            now + timedelta(days=365)
        ).isoformat()
    }