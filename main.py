from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from database.database import engine, get_db
from database import models

from schemas import UserRegister
from security import hash_password

from pki.certificate_service import issue_user_certificate

from pki.certificate_validator import validate_certificate

from pki.crl_service import revoke_certificate

# Create database tables
models.Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="PKI Call Authentication System",
    description="Prototype for certificate-based mutual authentication",
    version="1.0"
)


@app.get("/")
def root():
    return {
        "message": "PKI Call Authentication Server is running"
    }


@app.get("/health")
def health():
    return {
        "status": "OK"
    }


# --------------------------------------------------
# USER REGISTRATION
# --------------------------------------------------

@app.post("/register")
def register_user(
    user: UserRegister,
    db: Session = Depends(get_db)
):


    # --------------------------------------------
    # 1. Check duplicate phone
    # --------------------------------------------

    existing_user = (
        db.query(models.User)
        .filter(models.User.phone == user.phone)
        .first()
    )

    if existing_user:

        raise HTTPException(
            status_code=409,
            detail="Phone number already registered"
        )


    # --------------------------------------------
    # 2. Hash password
    # --------------------------------------------

    hashed_password = hash_password(
        user.password
    )


    # --------------------------------------------
    # 3. Create user
    # --------------------------------------------

    new_user = models.User(
        name=user.name,
        phone=user.phone,
        password_hash=hashed_password
    )

    db.add(new_user)

    # We need the generated user ID before
    # creating the certificate.
    db.flush()


    # --------------------------------------------
    # 4. Generate certificate automatically
    # --------------------------------------------

    try:

        certificate_info = issue_user_certificate(
            user_id=new_user.id,
            name=new_user.name,
            phone=new_user.phone
        )

    except Exception as error:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Certificate generation failed: {error}"
        )


    # --------------------------------------------
    # 5. Store certificate information
    # --------------------------------------------

    certificate_record = models.Certificate(

        user_id=new_user.id,

        serial_number=certificate_info[
            "serial_number"
        ],

        certificate_path=certificate_info[
            "certificate_path"
        ],

        private_key_path=certificate_info[
            "private_key_path"
        ],

        status="ACTIVE",

        issued_at=certificate_info[
            "issued_at"
        ],

        expires_at=certificate_info[
            "expires_at"
        ]
    )


    db.add(certificate_record)

    db.commit()

    db.refresh(new_user)
    db.refresh(certificate_record)


    # --------------------------------------------
    # 6. Return result
    # --------------------------------------------

    return {

        "message":
            "User registered and certificate issued successfully",

        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "phone": new_user.phone
        },

        "certificate": {
            "serial_number":
                certificate_record.serial_number,

            "status":
                certificate_record.status,

            "issued_at":
                certificate_record.issued_at,

            "expires_at":
                certificate_record.expires_at
        }
    }


@app.get("/certificate/verify/{user_id}")
def verify_user_certificate(
    user_id: int,
    db: Session = Depends(get_db)
):

    # -----------------------------------------
    # Find user
    # -----------------------------------------

    user = (
        db.query(models.User)
        .filter(models.User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )


    # -----------------------------------------
    # Find user's certificate
    # -----------------------------------------

    certificate = (
        db.query(models.Certificate)
        .filter(
            models.Certificate.user_id == user_id
        )
        .first()
    )

    if not certificate:
        raise HTTPException(
            status_code=404,
            detail="Certificate not found"
        )


    # -----------------------------------------
    # Check revocation/status
    # -----------------------------------------

    if certificate.status != "ACTIVE":

        return {
            "user_id": user.id,
            "name": user.name,
            "valid": False,
            "reason": "CERTIFICATE_REVOKED"
        }


    # -----------------------------------------
    # Cryptographically validate certificate
    # -----------------------------------------

    result = validate_certificate(
        certificate_path=certificate.certificate_path,
        expected_name=user.name,
        expected_user_id=user.id
    )


    return {
        "user_id": user.id,
        "name": user.name,
        **result
    }

@app.post("/certificate/revoke/{user_id}")
def revoke_user_certificate(
    user_id: int,
    db: Session = Depends(get_db)
):

    # Find user
    user = (
        db.query(models.User)
        .filter(models.User.id == user_id)
        .first()
    )

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )


    # Find certificate
    certificate = (
        db.query(models.Certificate)
        .filter(
            models.Certificate.user_id == user_id
        )
        .first()
    )

    if not certificate:

        raise HTTPException(
            status_code=404,
            detail="Certificate not found"
        )


    # Already revoked?
    if certificate.status == "REVOKED":

        raise HTTPException(
            status_code=409,
            detail="Certificate already revoked"
        )


    # Add certificate to CRL
    try:

        revoke_certificate(
            int(certificate.serial_number)
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"CRL update failed: {error}"
        )


    # Update database
    certificate.status = "REVOKED"

    db.commit()


    return {
        "message": "Certificate revoked successfully",
        "user_id": user.id,
        "name": user.name,
        "serial_number": certificate.serial_number,
        "status": "REVOKED"
    }