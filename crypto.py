from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class CryptoManager:
    @staticmethod
    def generate_key_pair():
        """Generate a new RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key):
        """Serialize public key to bytes"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def serialize_private_key(private_key, password):
        """Serialize and encrypt private key"""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
    
    @staticmethod
    def encrypt_file(file_data, public_key):
        """Encrypt file data using hybrid encryption"""
        try:
            # Generate a random symmetric key
            symmetric_key = os.urandom(32)
            
            # Generate a random IV
            iv = os.urandom(16)
            
            # Create cipher for symmetric encryption
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad the data
            pad_length = 16 - (len(file_data) % 16)
            padded_data = file_data + bytes([pad_length] * pad_length)
            
            # Encrypt the file data with symmetric key
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encrypt the symmetric key with RSA public key
            if isinstance(public_key, bytes):
                public_key = serialization.load_pem_public_key(public_key)
            
            encrypted_key = public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Combine IV, encrypted key, and encrypted data
            return base64.b64encode(iv + len(encrypted_key).to_bytes(4, 'big') + encrypted_key + encrypted_data)
            
        except Exception as e:
            raise Exception(f"Failed to encrypt file: {str(e)}")
    
    @staticmethod
    def decrypt_file(encrypted_data, private_key_data, password):
        """Decrypt file data using hybrid decryption"""
        try:
            # Decode the combined data
            combined_data = base64.b64decode(encrypted_data)
            
            # Extract IV, encrypted key length, encrypted key, and encrypted data
            iv = combined_data[:16]
            key_length = int.from_bytes(combined_data[16:20], 'big')
            encrypted_key = combined_data[20:20+key_length]
            encrypted_data = combined_data[20+key_length:]
            
            # Load the private key with password
            if isinstance(private_key_data, bytes):
                private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=password.encode()
                )
            else:
                private_key = private_key_data
            
            # Decrypt the symmetric key
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the file data
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            pad_length = padded_data[-1]
            data = padded_data[:-pad_length]
            
            return data
            
        except Exception as e:
            raise Exception(f"Failed to decrypt file: {str(e)}")
    
    @staticmethod
    def encrypt_private_key(private_key, password, salt):
        """Encrypt private key with password"""
        try:
            # Generate key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Create Fernet cipher
            f = Fernet(key)
            
            # Encrypt private key
            return f.encrypt(private_key)
        except Exception as e:
            raise Exception(f"Failed to encrypt private key: {str(e)}")
    
    @staticmethod
    def decrypt_private_key(encrypted_private_key, password, salt):
        """Decrypt private key with password"""
        try:
            # Generate key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Create Fernet cipher
            f = Fernet(key)
            
            # Decrypt private key
            return f.decrypt(encrypted_private_key)
        except Exception as e:
            raise Exception(f"Failed to decrypt private key: {str(e)}")