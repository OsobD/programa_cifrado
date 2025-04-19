import sqlite3
import os
from datetime import datetime

class Database:
    def __init__(self, db_path='data/encrypted_files.db'):
        self.db_path = db_path
        self.ensure_directory_exists()
        self.initialize_database()
    
    def ensure_directory_exists(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def initialize_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Crear tabla de usuarios
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            user_level INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Crear tabla de archivos encriptados
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            encryption_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            nonce BLOB NOT NULL,
            tag BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Crear tabla de intentos de descifrado
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS decryption_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            file_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            hostname TEXT,
            ip_address TEXT,
            success BOOLEAN,
            error_type TEXT,
            error_message TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (file_id) REFERENCES encrypted_files (id)
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_user(self, username, password_hash, salt, user_level=1):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, user_level) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, user_level)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
    
    def get_user(self, username):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, password_hash, salt, user_level FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        conn.close()
        return user
    
    def add_encrypted_file(self, user_id, original_filename, encrypted_filename, 
                           file_type, file_size, nonce, tag):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO encrypted_files 
               (user_id, original_filename, encrypted_filename, file_type, file_size, nonce, tag)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, original_filename, encrypted_filename, file_type, file_size, nonce, tag)
        )
        
        conn.commit()
        file_id = cursor.lastrowid
        conn.close()
        
        return file_id
    
    def get_encrypted_files_by_user(self, user_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT id, original_filename, encrypted_filename, file_type, file_size, 
               encryption_date, nonce, tag
               FROM encrypted_files WHERE user_id = ?
               ORDER BY encryption_date DESC""",
            (user_id,)
        )
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return files
    
    def get_file_info(self, file_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT id, user_id, original_filename, encrypted_filename, file_type, 
               file_size, encryption_date, nonce, tag
               FROM encrypted_files WHERE id = ?""",
            (file_id,)
        )
        
        file_info = cursor.fetchone()
        conn.close()
        
        return dict(file_info) if file_info else None
    
    def update_user_password(self, user_id, new_password_hash):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_password_hash, user_id)
        )
        
        conn.commit()
        success = cursor.rowcount > 0
        conn.close()
        
        return success
    
    def log_decryption_attempt(self, user_id, file_id, hostname, ip_address=None, success=False, error_type=None, error_message=None):
        """
        Registra un intento de descifrado en la base de datos, exitoso o fallido.
        
        Args:
            user_id (int): ID del usuario que realiza el intento
            file_id (int): ID del archivo que se intenta descifrar
            hostname (str): Nombre del host desde donde se realiza el intento
            ip_address (str, opcional): Dirección IP desde donde se realiza el intento
            success (bool): Si el intento fue exitoso (True) o fallido (False)
            error_type (str, opcional): Tipo de error en caso de fallo
            error_message (str, opcional): Mensaje de error en caso de fallo
            
        Returns:
            int: ID del registro de intento creado
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO decryption_attempts 
               (user_id, file_id, hostname, ip_address, success, error_type, error_message)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, file_id, hostname, ip_address, success, error_type, error_message)
        )
        
        conn.commit()
        attempt_id = cursor.lastrowid
        conn.close()
        
        return attempt_id
        
    def get_decryption_attempts(self, user_id=None, file_id=None, limit=50):
        """
        Obtiene los intentos de descifrado registrados, opcionalmente filtrados por usuario o archivo.
        
        Args:
            user_id (int, opcional): Filtrar por ID de usuario
            file_id (int, opcional): Filtrar por ID de archivo
            limit (int): Número máximo de registros a devolver
            
        Returns:
            list: Lista de diccionarios con la información de los intentos
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """SELECT d.id, d.timestamp, d.hostname, d.ip_address, d.success, 
                  d.error_type, d.error_message, u.username, f.original_filename
                  FROM decryption_attempts d
                  JOIN users u ON d.user_id = u.id
                  JOIN encrypted_files f ON d.file_id = f.id
                  WHERE 1=1"""
                  
        params = []
        
        if user_id is not None:
            query += " AND d.user_id = ?"
            params.append(user_id)
            
        if file_id is not None:
            query += " AND d.file_id = ?"
            params.append(file_id)
            
        query += " ORDER BY d.timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        attempts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return attempts 