import os
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger("NIST-CLOUD-SECURE")

# Secure data-at-rest encryption key configuration (NIST compliance)
ENCRYPTION_KEY = os.environ.get("ENC_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# Strict Supabase / PostgreSQL Configuration (No local SQLite storage permitted)
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL or "sqlite" in DATABASE_URL:
    raise ValueError(
        "CRITICAL SECURITY CONFIGURATION ERROR: Local SQLite storage is strictly disabled "
        "to comply with data governance policies. A valid remote Supabase / PostgreSQL "
        "DATABASE_URL environment variable must be provided."
    )

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Enforce secure SSL connection for Supabase cloud PostgreSQL (GDPR / NIST requirement)
if "sslmode" not in DATABASE_URL:
    separator = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL = f"{DATABASE_URL}{separator}sslmode=require"

# Initialize engine with connection pooling and security timeout parameters
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True, 
    pool_size=10, 
    max_overflow=20,
    connect_args={"connect_timeout": 10}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ClientModel(Base):
    __tablename__ = "client_ledger"
    hw_id = Column(String(64), primary_key=True)
    api_key = Column(String(128), unique=True, index=True)
    status = Column(String(32), default="PENDING")
    subscription_tier = Column(String(32), default="PRO")
    balance_tokens = Column(Integer, default=50000)
    metadata_json = Column(Text, nullable=True)  # Designed for encrypted PII/metadata payload storage
    created_at = Column(DateTime, default=datetime.utcnow)

class TrafficLogModel(Base):
    __tablename__ = "encrypted_traffic_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    hw_id = Column(String(64), index=True)
    provider = Column(String(64), default="Groq/Gemini")
    model = Column(String(64), default="Gemini 2.5 Flash")
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    latency_ms = Column(Integer, default=120)
    payload_json = Column(Text)  # Stores encrypted audit logs for compliance tracking
    created_at = Column(DateTime, default=datetime.utcnow)

# Enforce remote schema creation strictly on the Supabase cluster
Base.metadata.create_all(bind=engine)