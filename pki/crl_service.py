from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from datetime import datetime, timedelta, timezone
from pathlib import Path

from pki.ca import (
    CA_PRIVATE_KEY_PATH,
    CA_CERTIFICATE_PATH
)


CRL_PATH = Path("certificates/ca/crl.pem")


def load_ca():

    with open(CA_PRIVATE_KEY_PATH, "rb") as file:
        ca_private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )

    with open(CA_CERTIFICATE_PATH, "rb") as file:
        ca_certificate = x509.load_pem_x509_certificate(
            file.read()
        )

    return ca_private_key, ca_certificate


def load_crl():

    if not CRL_PATH.exists():
        return None

    with open(CRL_PATH, "rb") as file:
        return x509.load_pem_x509_crl(
            file.read()
        )


def revoke_certificate(serial_number: int):

    ca_private_key, ca_certificate = load_ca()

    old_crl = load_crl()

    now = datetime.now(timezone.utc)


    # -----------------------------------------
    # Create a new CRL
    # -----------------------------------------

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_certificate.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )


    # -----------------------------------------
    # Preserve certificates already revoked
    # -----------------------------------------

    if old_crl:

        for revoked_certificate in old_crl:

            # Avoid adding the same serial twice
            if revoked_certificate.serial_number == serial_number:
                continue

            builder = builder.add_revoked_certificate(
                revoked_certificate
            )


    # -----------------------------------------
    # Add newly revoked certificate
    # -----------------------------------------

    revoked_certificate = (
        x509.RevokedCertificateBuilder()

        .serial_number(serial_number)

        .revocation_date(now)

        .build()
    )


    builder = builder.add_revoked_certificate(
        revoked_certificate
    )


    # -----------------------------------------
    # CA signs CRL
    # -----------------------------------------

    crl = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256()
    )


    # -----------------------------------------
    # Save CRL
    # -----------------------------------------

    with open(CRL_PATH, "wb") as file:

        file.write(
            crl.public_bytes(
                serialization.Encoding.PEM
            )
        )


def is_certificate_revoked(serial_number: int):

    crl = load_crl()

    if crl is None:
        return False

    for revoked_certificate in crl:

        if revoked_certificate.serial_number == serial_number:
            return True

    return False