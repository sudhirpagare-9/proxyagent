import os
from cryptography.fernet import Fernet
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./enterprise_gateway.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

ENCRYPTION_KEY = os.environ.get("ENC_KEY", Fernet.generate_key().decode()).encode()
cipher = Fernet(ENCRYPTION_KEY)

class ClientModel(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    hw_id = Column(String, unique=True, index=True)
    api_key = Column(String, unique=True, index=True)
    status = Column(String, default="APPROVED")
    subscription_tier = Column(String, default="PRO")
    balance_tokens = Column(Integer, default=50000)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class TrafficLogModel(Base):
    __tablename__ = "traffic_logs"
    id = Column(Integer, primary_key=True, index=True)
    hw_id = Column(String, index=True)
    provider = Column(String)
    model = Column(String)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    payload_json = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

def init_db():
    Base.metadata.create_all(bind=engine)