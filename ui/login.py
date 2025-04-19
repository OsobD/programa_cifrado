from PyQt5.QtWidgets import (QDialog, QLabel, QLineEdit, QPushButton, 
                           QVBoxLayout, QHBoxLayout, QMessageBox, QCheckBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon

class LoginDialog(QDialog):
    def __init__(self, auth, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.user_data = None
        self.setup_ui()
    
    # Estilos de UI
    def setup_ui(self):
        self.setWindowTitle("OsobCrypter - Acceso")
        self.setMinimumWidth(400)
        self.setStyleSheet("""
            QDialog {
                background-color: #172424;
                color: #e0e0e0;
            }
            QLabel {
                font-size: 14px;
                color: #e0e0e0;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #444444;
                border-radius: 4px;
                background-color: #253535;
                color: #e0e0e0;
                font-size: 13px;
            }
            QPushButton {
                padding: 8px 16px;
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1c6ea4;
            }
            QPushButton#register_btn {
                background-color: #2ecc71;
            }
            QPushButton#register_btn:hover {
                background-color: #27ae60;
            }
        """)
        
        # Create widgets
        self.title_label = QLabel("OsobCrypter")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 20px;")
        
        self.username_label = QLabel("Usuario:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Ingrese su nombre de usuario")
        
        self.password_label = QLabel("Contraseña:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Ingrese su contraseña")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.login_btn = QPushButton("Iniciar Sesión")
        self.login_btn.clicked.connect(self.login)
        
        self.register_btn = QPushButton("Registrarse")
        self.register_btn.setObjectName("register_btn")
        self.register_btn.clicked.connect(self.register)
        
        # Layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.title_label)
        
        form_layout = QVBoxLayout()
        form_layout.addWidget(self.username_label)
        form_layout.addWidget(self.username_input)
        form_layout.addSpacing(10)
        form_layout.addWidget(self.password_label)
        form_layout.addWidget(self.password_input)
        
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.login_btn)
        buttons_layout.addWidget(self.register_btn)
        
        main_layout.addLayout(form_layout)
        main_layout.addSpacing(20)
        main_layout.addLayout(buttons_layout)
        
        self.setLayout(main_layout)
    
    # Funciones de login y registro
    def login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Advertencia", "Por favor ingrese usuario y contraseña.")
            return
        
        success, result = self.auth.login(username, password)
        
        if success:
            self.user_data = result
            self.accept()
        else:
            QMessageBox.critical(self, "Error de Inicio de Sesión", result)
    
    def register(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Advertencia", "Por favor ingrese usuario y contraseña.")
            return
        
        if len(password) < 8:
            QMessageBox.warning(self, "Advertencia", "La contraseña debe tener al menos 8 caracteres.")
            return
        
        success, result = self.auth.register_user(username, password)
        
        if success:
            QMessageBox.information(self, "Éxito", f"Usuario {username} registrado exitosamente. Ahora puede iniciar sesión.")
            self.password_input.clear()
        else:
            QMessageBox.critical(self, "Error de Registro", result)
    
    def get_user_data(self):
        return self.user_data 