import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw
import argon2

class CryptoManager:
    def __init__(self, security_level="medium"):
        self.set_security_level(security_level)
    
    def set_security_level(self, level):
        """Set security parameters based on the security level"""
        if level == "low":
            self.time_cost = 2
            self.memory_cost = 32768  # 32 MB
            self.parallelism = 2
        elif level == "high":
            self.time_cost = 4
            self.memory_cost = 131072  # 128 MB
            self.parallelism = 8
        else:  # medium (default)
            self.time_cost = 3
            self.memory_cost = 65536  # 64 MB
            self.parallelism = 4
        
        self.hash_len = 32  # Output hash length
        self.salt_len = 16  # Salt length
    
    def derive_key(self, password, salt=None):
        """Derive an encryption key from a password using Argon2"""
        if salt is None:
            salt = os.urandom(self.salt_len)
        
        # Use Argon2id for key derivation (memory-hard)
        raw_key = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            type=argon2.low_level.Type.ID
        )
        
        return raw_key, salt
    
    def encrypt_file(self, file_path, password):
        """Encrypt a file using AES-256-GCM with Argon2 key derivation"""
        try:
            # Read the file
            with open(file_path, 'rb') as file:
                plaintext = file.read()
            
            # Derive key using Argon2
            salt = os.urandom(self.salt_len)
            key, _ = self.derive_key(password, salt)
            
            # Generate a random nonce
            nonce = os.urandom(12)
            
            # Encrypt the data
            aesgcm = AESGCM(key)
            ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
            
            # AESGCM in cryptography combines ciphertext and tag
            # The tag is the last 16 bytes
            ciphertext = ciphertext_and_tag[:-16]
            tag = ciphertext_and_tag[-16:]
            
            # Create encrypted file path
            file_name = os.path.basename(file_path)
            encrypted_file_path = os.path.join(
                os.path.dirname(file_path),
                f"{file_name}.encrypted"
            )
            
            # Write the encrypted data to a new file
            with open(encrypted_file_path, 'wb') as encrypted_file:
                # Write format: salt + nonce + ciphertext (tag is stored separately in DB)
                encrypted_file.write(salt)
                encrypted_file.write(nonce)
                encrypted_file.write(ciphertext)
            
            # Return metadata
            return {
                'original_filename': file_name,
                'encrypted_filename': f"{file_name}.encrypted",
                'file_size': len(plaintext),
                'file_type': os.path.splitext(file_name)[1][1:] or 'unknown',
                'encrypted_file_path': encrypted_file_path,
                'nonce': nonce,
                'tag': tag
            }
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_file_path, password, output_path, nonce, tag):
        """Decrypt a file using AES-256-GCM with Argon2 key derivation"""
        try:
            # Read the encrypted file
            with open(encrypted_file_path, 'rb') as encrypted_file:
                salt = encrypted_file.read(self.salt_len)
                file_nonce = encrypted_file.read(12)  # We'll use the stored nonce from DB
                ciphertext = encrypted_file.read()
            
            # Derive key using Argon2 with the same salt
            key, _ = self.derive_key(password, salt)
            
            # Decrypt the data
            aesgcm = AESGCM(key)
            
            # For decryption, we need to append the tag to the ciphertext
            ciphertext_and_tag = ciphertext + tag
            
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
            
            # Write the decrypted data to a new file
            with open(output_path, 'wb') as decrypted_file:
                decrypted_file.write(plaintext)
                
            return True
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}") 