"""
models.py — Modèles SQLAlchemy correspondant au schéma MySQL existant
Permet de remplacer les requêtes SQL brutes par des opérations ORM.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Index,
    create_engine, event
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
import os
import logging

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    role = Column(Enum('user', 'admin', name='user_role'), nullable=False, default='user')
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    updated_at = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    # Relations
    sessions = relationship('Session', back_populates='user', cascade='all, delete-orphan')
    mfa_secret = relationship('MfaSecret', back_populates='user', uselist=False, cascade='all, delete-orphan')
    recovery_codes = relationship('MfaRecoveryCode', back_populates='user', cascade='all, delete-orphan')
    totp_used_codes = relationship('TotpUsedCode', back_populates='user', cascade='all, delete-orphan')


class LoginAttempt(Base):
    __tablename__ = 'login_attempts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    identifier = Column(String(255), nullable=False)
    identifier_type = Column(
        Enum('ip', 'username', 'user_ip', name='identifier_type_enum'),
        nullable=False, default='username'
    )
    attempted_at = Column(DateTime, nullable=False, default=datetime.now)
    success = Column(Boolean, nullable=False, default=False)
    ip_address = Column(String(45))

    __table_args__ = (
        Index('idx_identifier_type_time', 'identifier', 'identifier_type', 'attempted_at'),
        Index('idx_ip_time', 'ip_address', 'attempted_at'),
    )


class Session(Base):
    __tablename__ = 'sessions'

    session_token = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now)
    expires_at = Column(DateTime, nullable=False)
    invalidated = Column(Boolean, nullable=False, default=False)
    mfa_verified = Column(Boolean, nullable=False, default=False)
    ip_address = Column(String(45))

    user = relationship('User', back_populates='sessions')


class MfaSecret(Base):
    __tablename__ = 'mfa_secrets'

    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    totp_secret = Column(String(255), nullable=False)
    validated = Column(Boolean, nullable=False, default=False)
    validated_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=datetime.now)

    user = relationship('User', back_populates='mfa_secret')


class MfaRecoveryCode(Base):
    __tablename__ = 'mfa_recovery_codes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    code_hash = Column(String(255), nullable=False)
    used = Column(Boolean, nullable=False, default=False)
    used_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=datetime.now)

    user = relationship('User', back_populates='recovery_codes')

    __table_args__ = (
        Index('idx_user_unused', 'user_id', 'used'),
    )


class TotpUsedCode(Base):
    __tablename__ = 'totp_used_codes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    code_hash = Column(String(64), nullable=False)
    used_at = Column(DateTime, nullable=False, default=datetime.now)

    user = relationship('User', back_populates='totp_used_codes')

    __table_args__ = (
        Index('idx_user_code_time', 'user_id', 'code_hash', 'used_at'),
    )


# ---------------------------------------------------------------------------
# Engine & Session Factory
# ---------------------------------------------------------------------------
_engine = None
_SessionFactory = None


def get_engine():
    """Crée ou retourne le moteur SQLAlchemy (MySQL)."""
    global _engine
    if _engine is None:
        db_user = os.environ.get("DB_USER", "app_user")
        db_password = os.environ.get("DB_PASSWORD", "")
        db_host = os.environ.get("DB_HOST", "localhost")
        db_port = int(os.environ.get("DB_PORT", 3306))
        db_name = os.environ.get("DB_NAME", "secure_auth")

        url = f"mysql+mysqlconnector://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}?charset=utf8mb4"
        _engine = create_engine(
            url,
            pool_size=5,
            pool_recycle=3600,
            pool_pre_ping=True,
            echo=False,
        )
        logger.info("Moteur SQLAlchemy initialisé.")
    return _engine


def get_session_factory():
    """Retourne la fabrique de sessions SQLAlchemy (scoped)."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = scoped_session(sessionmaker(bind=get_engine()))
    return _SessionFactory


def get_db_session():
    """Fournit une session SQLAlchemy. Usage : with get_db_session() as session: ..."""
    factory = get_session_factory()
    session = factory()
    return session


def init_db_orm():
    """Crée les tables si elles n'existent pas (via SQLAlchemy)."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    logger.info("Schéma de base de données initialisé via ORM.")
