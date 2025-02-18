from sqlalchemy.orm import Session
from models import User, FileKey

def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_file_keys_by_user(db: Session, user_id: int):
    return db.query(FileKey).filter(FileKey.owner_id == user_id).all()

def create_user(db: Session, user: User):
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def save_file_key(db: Session, file_key: FileKey):
    db.add(file_key)
    db.commit()
    db.refresh(file_key)
    return file_key