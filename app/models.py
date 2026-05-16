from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    preferences = Column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
        server_default=text(
            '\'{"order_updates": true, "market_alerts": true, '
            '"email_notifications": false, "compact_account_view": false}\''
        ),
    )
    is_suspended = Column(Boolean, nullable=False, default=False, server_default="false")
    suspended_reason = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
