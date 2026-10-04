from sqlalchemy import Column, Integer, String, ForeignKey
from database.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False
    )

    phone = Column(
        String,
        unique=True,
        nullable=False
    )

    password_hash = Column(
        String,
        nullable=False
    )


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    serial_number = Column(
        String,
        unique=True,
        nullable=False
    )

    certificate_path = Column(
        String,
        nullable=False
    )

    private_key_path = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        nullable=False,
        default="ACTIVE"
    )

    issued_at = Column(
        String,
        nullable=False
    )

    expires_at = Column(
        String,
        nullable=False
    )