import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw
import argon2

class CryptoManager:
    """
    Administrador de operaciones criptográficas para el cifrado y descifrado de archivos.
    
    Esta clase da métodos para cifrar y descifrar archivos utilizando
    AES-256-GCM con derivación de claves Argon2. Permite configurar diferentes
    niveles de seguridad que afectan a los parámetros de Argon2.
    
    Atributos:
        time_cost (int): Costo de tiempo para Argon2
        memory_cost (int): Costo de memoria para Argon2 (en bytes)
        parallelism (int): Nivel de paralelismo para Argon2
        hash_len (int): Longitud de salida del hash
        salt_len (int): Longitud de la sal
    """
    def __init__(self, security_level="medium"):
        """
        Inicia un nuevo administrador criptográfico.
        
        Args:
            security_level (str): Nivel de seguridad, puede ser "low", "medium" o "high".
                                  Por defecto es "medium".
        """
        self.set_security_level(security_level)
    
    def set_security_level(self, level):
        """
        Establece los parámetros de seguridad basados en el nivel de seguridad.
        
        Los niveles de seguridad afectan a los parámetros de Argon2 para la
        derivación de claves, balanceando seguridad y rendimiento.
        
        Args:
            level (str): Nivel de seguridad, puede ser "low", "medium" o "high".
        """
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
        """
        Deriva una clave de cifrado a partir de una contraseña utilizando Argon2.
        
        Utiliza el algoritmo Argon2id, que es resistente a ataques por hardware
        especializado y de canal lateral.
        
        Args:
            password (str): La contraseña de la que derivar la clave.
            salt (bytes, opcional): La sal a utilizar. Si no se proporciona, se genera una aleatoria.
        
        Returns:
            tuple: Una tupla (clave_derivada, sal), donde clave_derivada son los bytes de la clave
                  y sal son los bytes de la sal utilizada.
        """
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
        """
        Cifra un archivo utilizando AES-256-GCM con derivación de clave Argon2.
        
        Este método lee un archivo, lo cifra, y guarda el resultado en un nuevo archivo
        con la extensión .encrypted. La sal y el nonce se almacenan junto con los datos
        cifrados, mientras que la etiqueta de autenticación se devuelve por separado.
        
        Args:
            file_path (str): Ruta al archivo a cifrar.
            password (str): Contraseña para cifrar el archivo.
        
        Returns:
            dict: Un diccionario con metadatos sobre el archivo cifrado, incluyendo:
                - original_filename: Nombre del archivo original
                - encrypted_filename: Nombre del archivo cifrado
                - file_size: Tamaño del archivo original
                - file_type: Tipo de archivo basado en la extensión
                - encrypted_file_path: Ruta completa al archivo cifrado
                - nonce: Nonce utilizado para el cifrado
                - tag: Etiqueta de autenticación
        
        Raises:
            Exception: Si el cifrado falla por cualquier razón.
        """
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
        """
        Descifra un archivo utilizando AES-256-GCM con derivación de clave Argon2.
        
        Este método lee un archivo cifrado y lo descifra utilizando la contraseña proporcionada,
        el nonce y la etiqueta de autenticación. El resultado se guarda en la ruta de salida
        especificada.
        
        Args:
            encrypted_file_path (str): Ruta al archivo cifrado.
            password (str): Contraseña para descifrar el archivo.
            output_path (str): Ruta donde guardar el archivo descifrado.
            nonce (bytes): Nonce utilizado durante el cifrado.
            tag (bytes): Etiqueta de autenticación.
        
        Returns:
            bool: True si el descifrado fue exitoso.
        
        Raises:
            Exception: Si el descifrado falla por cualquier razón.
        """
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