from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from datetime import datetime, timezone
from pathlib import Path

from pki.ca import CA_CERTIFICATE_PATH

from pki.crl_service import is_certificate_revoked


def validate_certificate(
    certificate_path: str,
    expected_name: str,
    expected_user_id: int
):

    # ---------------------------------------------
    # 1. Check certificate file exists
    # ---------------------------------------------

    cert_path = Path(certificate_path)

    if not cert_path.exists():
        return {
            "valid": False,
            "reason": "CERTIFICATE_NOT_FOUND"
        }


    # ---------------------------------------------
    # 2. Load user's certificate
    # ---------------------------------------------

    try:
        with open(cert_path, "rb") as file:
            certificate = x509.load_pem_x509_certificate(
                file.read()
            )
    except Exception:
        return {
            "valid": False,
            "reason": "INVALID_CERTIFICATE_FORMAT"
        }


    # ---------------------------------------------
    # 3. Load trusted CA certificate
    # ---------------------------------------------

    try:
        with open(CA_CERTIFICATE_PATH, "rb") as file:
            ca_certificate = x509.load_pem_x509_certificate(
                file.read()
            )
    except Exception:
        return {
            "valid": False,
            "reason": "CA_CERTIFICATE_NOT_FOUND"
        }


    # ---------------------------------------------
    # 4. Check trusted issuer
    # ---------------------------------------------

    if certificate.issuer != ca_certificate.subject:
        return {
            "valid": False,
            "reason": "UNTRUSTED_ISSUER"
        }


    # ---------------------------------------------
    # 5. Verify CA's digital signature
    # ---------------------------------------------

    ca_public_key = ca_certificate.public_key()

    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(
                certificate.signature_hash_algorithm
            )
        )

    except InvalidSignature:
        return {
            "valid": False,
            "reason": "INVALID_CA_SIGNATURE"
        }

    except Exception:
        return {
            "valid": False,
            "reason": "SIGNATURE_VERIFICATION_FAILED"
        }


    # ---------------------------------------------
    # 6. Check validity / expiration
    # ---------------------------------------------

    now = datetime.now(timezone.utc)

    if now < certificate.not_valid_before_utc:
        return {
            "valid": False,
            "reason": "CERTIFICATE_NOT_YET_VALID"
        }

    if now > certificate.not_valid_after_utc:
        return {
            "valid": False,
            "reason": "CERTIFICATE_EXPIRED"
        }

# ---------------------------------------------
# Check Certificate Revocation List
# ---------------------------------------------

    if is_certificate_revoked(
    certificate.serial_number
    ):
         return {
            "valid": False,
            "reason": "CERTIFICATE_REVOKED"
    }


    # ---------------------------------------------
    # 7. Check name in certificate
    # ---------------------------------------------

    try:
        certificate_name = (
            certificate.subject
            .get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0]
            .value
        )

    except (IndexError, AttributeError):
        return {
            "valid": False,
            "reason": "CERTIFICATE_NAME_MISSING"
        }


    if certificate_name != expected_name:
        return {
            "valid": False,
            "reason": "IDENTITY_NAME_MISMATCH"
        }


    # ---------------------------------------------
    # 8. Check user ID in certificate
    # ---------------------------------------------

    try:
        certificate_user_id = (
            certificate.subject
            .get_attributes_for_oid(
                x509.NameOID.USER_ID
            )[0]
            .value
        )

    except (IndexError, AttributeError):
        return {
            "valid": False,
            "reason": "CERTIFICATE_USER_ID_MISSING"
        }


    if certificate_user_id != str(expected_user_id):
        return {
            "valid": False,
            "reason": "IDENTITY_USER_ID_MISMATCH"
        }


    # ---------------------------------------------
    # Everything passed
    # ---------------------------------------------

    return {
        "valid": True,
        "reason": "CERTIFICATE VALID",
        "serial_number": str(
            certificate.serial_number
        ),
        "subject": certificate_name
    }