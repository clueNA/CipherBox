import os
import hashlib
from crypto import CryptoManager

class UserManager:
    @staticmethod
    def create_user(db_session, username, password):
        """Create a new user with encryption keys"""
        from models import User  # Import here to avoid circular imports
        
        try:
            # Check if username already exists
            if db_session.query(User).filter(User.username == username).first():
                raise ValueError("Username already exists")
            
            # Generate salt for password and key encryption
            salt = os.urandom(16)
            
            # Generate key pair
            private_key, public_key = CryptoManager.generate_key_pair()
            
            # Serialize keys
            serialized_public_key = CryptoManager.serialize_public_key(public_key)
            serialized_private_key = CryptoManager.serialize_private_key(private_key, password)
            
            # Encrypt private key with password
            encrypted_private_key = CryptoManager.encrypt_private_key(
                serialized_private_key,
                password,
                salt
            )
            
            # Hash password with salt
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                salt,
                100000
            ).hex()
            
            # Create new user
            new_user = User(
                username=username,
                password_hash=password_hash,
                public_key=serialized_public_key,
                encrypted_private_key=encrypted_private_key,
                salt=salt
            )
            
            db_session.add(new_user)
            db_session.commit()
            
            return new_user
            
        except Exception as e:
            db_session.rollback()
            raise Exception(f"Registration failed: {str(e)}")

    @staticmethod
    def authenticate_user(db_session, username, password):
        """Authenticate a user"""
        from models import User  # Import here to avoid circular imports
        
        try:
            user = db_session.query(User).filter(User.username == username).first()
            
            if not user:
                return None
            
            # Hash provided password with user's salt
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                user.salt,
                100000
            ).hex()
            
            if password_hash == user.password_hash:
                return user
                
            return None
            
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return None

class FileManager:
    @staticmethod
    def save_file_key(db_session, filename, encrypted_data, encrypted_key, user):
        """Save encrypted file key"""
        from models import FileKey  # Import here to avoid circular imports
        
        try:
            # Calculate file hash
            file_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            # Create new file key
            new_file_key = FileKey(
                filename=filename,
                file_hash=file_hash,
                encrypted_key=encrypted_key,
                owner=user
            )
            
            db_session.add(new_file_key)
            db_session.commit()
            
            return new_file_key
            
        except Exception as e:
            db_session.rollback()
            raise Exception(f"Failed to save file key: {str(e)}")

    @staticmethod
    def get_file_key(db_session, encrypted_data, user_id):
        """Get file key by hash"""
        from models import FileKey  # Import here to avoid circular imports
        
        try:
            # Calculate file hash
            file_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            # Find file key
            return db_session.query(FileKey).filter(
                FileKey.file_hash == file_hash,
                FileKey.owner_id == user_id
            ).first()
            
        except Exception as e:
            print(f"Error getting file key: {str(e)}")
            return None

    @staticmethod
    def get_user_files(db_session, user_id):
        """Get all files for a user"""
        from models import FileKey  # Import here to avoid circular imports
        
        try:
            return db_session.query(FileKey).filter(
                FileKey.owner_id == user_id
            ).order_by(FileKey.created_at.desc()).all()
            
        except Exception as e:
            print(f"Error getting user files: {str(e)}")
            return []