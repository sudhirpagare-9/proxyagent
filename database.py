import os
from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Dynamic Database URL Configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./proxy_security_enterprise.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Configure Engine with automated fallback for DNS or connection failures
try:
    if "sqlite" in DATABASE_URL:
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    else:
        # Test connection with a short timeout to catch invalid hostnames immediately
        test_engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"connect_timeout": 5})
        with test_engine.connect() as connection:
            pass
        engine = test_engine
        print("[Enterprise Security] Successfully connected to Cloud PostgreSQL database.")
except Exception as e:
    print(f"[Enterprise Security Warning] Cloud DB connection failed: {e}")
    print("[Enterprise Security Warning] Falling back to local persistent SQLite storage to maintain uptime.")
    DATABASE_URL = "sqlite:///./proxy_security_enterprise.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ClientModel(Base):
    __tablename__ = "clients"
    hw_id = Column(String(64), primary_key=True)
    api_key = Column(String(128))
    status = Column(String(32), default="PENDING")
    subscription_tier = Column(String(32), default="PRO")
    balance_tokens = Column(Integer, default=50000)
    created_at = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(Text)


class TrafficLogModel(Base):
    __tablename__ = "traffic_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    hw_id = Column(String(64))
    payload_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)