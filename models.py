
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask_login import UserMixin
from sqlalchemy import Text, UniqueConstraint
from sqlalchemy.orm import validates

from extensions import db

password_hasher = PasswordHasher()


def utc_now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now
    )

    scans = db.relationship(
        "Scan", back_populates="user", cascade="all, delete-orphan"
    )
    login_events = db.relationship(
        "LoginEvent", back_populates="user", cascade="all, delete-orphan"
    )

    @validates("email")
    def normalize_email(self, _key, value):
        if not isinstance(value, str):
            raise ValueError("Email must be text.")
        return value.strip().lower()

    def set_password(self, password):
        if not isinstance(password, str):
            raise ValueError("Password must be text.")
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters.")
        if len(password) > 1024:
            raise ValueError("Password is too long.")
        self.password_hash = password_hasher.hash(password)

    def check_password(self, password):
        if not isinstance(password, str):
            return False
        try:
            return password_hasher.verify(self.password_hash, password)
        except (VerificationError, InvalidHashError, ValueError):
            return False

    def needs_password_rehash(self):
        try:
            return password_hasher.check_needs_rehash(self.password_hash)
        except (InvalidHashError, ValueError):
            return False


class Scan(db.Model):
    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint("id", "user_id", name="uq_scan_id_user_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    filename = db.Column(db.String(255), nullable=False)
    analysis_status = db.Column(
        db.String(30), nullable=False, default="partial"
    )
    findings_count = db.Column(db.Integer, nullable=False, default=0)
    report_json = db.Column(Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now
    )

    user = db.relationship("User", back_populates="scans")


class LoginEvent(db.Model):
    __tablename__ = "login_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    user_agent = db.Column(db.String(300), nullable=True)
    location = db.Column(db.String(120), nullable=True)

    user = db.relationship("User", back_populates="login_events")
