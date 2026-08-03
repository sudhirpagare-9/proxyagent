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
    os.makedirs("/data", exist_ok=True)
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ClientModel(Base):
    __tablename__ = "client_ledger"
    hw_id = Column(String(64), primary_key=True)
    api_key = Column(String(128), unique=True, index=True)
    status = Column(String(32), default="PENDING")
    subscription_tier = Column(String(32), default="PRO")
    balance_tokens = Column(Integer, default=50000)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class TrafficLogModel(Base):
    __tablename__ = "encrypted_traffic_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    hw_id = Column(String(64), index=True)
    payload_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)