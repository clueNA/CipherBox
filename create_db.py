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

def create_database():
    """Create a new database with all necessary tables."""
    try:
        # Remove existing database if it exists
        if os.path.exists(DATABASE_NAME):
            os.remove(DATABASE_NAME)
            print(f"Removed existing database: {DATABASE_NAME}")
        
        # Create new database and tables
        engine = create_engine(DATABASE_URL)
        Base.metadata.create_all(engine)
        print(f"Created new database: {DATABASE_NAME}")
        print("Database tables created successfully!")
        return True
    except Exception as e:
        print(f"Error creating database: {str(e)}")
        return False

if __name__ == "__main__":
    print("Starting database creation...")
    if create_database():
        print("""
Database created successfully!
You can now run the main application with:
> streamlit run app.py
        """)
    else:
        print("Failed to create database. Please check the error messages above.")