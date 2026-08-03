import os
from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Dynamic Database URL Configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./proxy_security_enterprise.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Configure Engine with SQLite Thread Safety or Postgres Pool Pre-Ping
if "sqlite" in DATABASE_URL:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

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