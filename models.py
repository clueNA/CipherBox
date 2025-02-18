from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import os

# Database configuration
DATABASE_NAME = "secure_database.db"
DATABASE_URL = f"sqlite:///{DATABASE_NAME}"

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    public_key = Column(LargeBinary)
    encrypted_private_key = Column(LargeBinary)
    salt = Column(LargeBinary)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    files = relationship("FileKey", back_populates="owner")

class FileKey(Base):
    __tablename__ = 'file_keys'
    
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    file_hash = Column(String)
    encrypted_key = Column(LargeBinary)
    owner_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    owner = relationship("User", back_populates="files")

def init_db():
    """Initialize the database, creating tables if they don't exist."""
    engine = create_engine(DATABASE_URL)
    
    # Create tables only if they don't exist
    Base.metadata.create_all(engine)
    
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()

def get_db_session():
    """Get a database session."""
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()