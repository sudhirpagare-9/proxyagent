import os
from datetime import datetime
from cryptography.fernet import Fernet
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Secure data-at-rest encryption key configuration
ENCRYPTION_KEY = os.environ.get("ENC_KEY", Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# Dynamic URL: Checks Render environment for PostgreSQL or defaults to a persistent path
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:////data/secure_ai_gateway.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if "sqlite" in DATABASE_URL:
    # Ensure local directory exists if running with a disk mount
    os.makedirs("/data", exist_ok=True)
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ClientLedgerModel(Base):
    __tablename__ = "client_ledger"
    hw_id = Column(String(64), primary_key=True, default="cloud-user")
    balance_tokens = Column(Integer, default=100000)
    total_consumed = Column(Integer, default=0)

class EncryptedTrafficLog(Base):
    __tablename__ = "encrypted_traffic_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    hw_id = Column(String(64))
    encrypted_payload = Column(Text)
    tokens_used = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)