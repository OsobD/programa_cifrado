import os
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QPushButton, QLabel, QTableWidget, QTableWidgetItem,
                           QFileDialog, QMessageBox, QTabWidget, QLineEdit,
                           QFormLayout, QComboBox, QGroupBox, QHeaderView, 
                           QSplitter, QFrame, QDialog, QProgressBar, QInputDialog)
from PyQt5.QtCore import Qt, QSize, QTimer
from PyQt5.QtGui import QIcon, QFont
from datetime import datetime

from utils.notifications import NotificationManager

class MainWindow(QMainWindow):
    def __init__(self, crypto_manager, db, user_data):
        super().__init__()
        self.crypto_manager = crypto_manager
        self.db = db
        self.user_data = user_data
        self.current_theme = "Dark"
        
        # Inicializar el gestor de notificaciones
        self.notification_manager = NotificationManager(db)
        
        # Configurar temporizador para verificar notificaciones periódicamente
        self.notification_timer = QTimer(self)
        self.notification_timer.timeout.connect(self.check_notifications)
        self.notification_timer.start(60000)  # Verificar cada minuto
        
        self.setup_ui()
        self.load_user_files()
        
        # Verificar notificaciones al iniciar
        QTimer.singleShot(1000, self.check_notifications)
    
    def setup_ui(self):
        self.setWindowTitle("Encriptador de Archivos Seguro")
        self.setMinimumSize(900, 600)
        self.apply_theme(self.current_theme)
        
        # Central widget
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Header with user info
        header_layout = QHBoxLayout()
        welcome_label = QLabel(f"Bienvenido, {self.user_data['username']}")
        welcome_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        logout_btn = QPushButton("Cerrar Sesión")
        logout_btn.setFixedWidth(120)
        logout_btn.setFixedHeight(30)
        logout_btn.setStyleSheet("""
            background-color: #e74c3c;
            color: white;
            border-radius: 5px;
            font-weight: bold;
            font-size: 12px;
        """)
        logout_btn.clicked.connect(self.logout)
        
        header_layout.addWidget(welcome_label)
        header_layout.addStretch(1)
        header_layout.addWidget(logout_btn)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        file_tab = self.create_file_tab()
        history_tab = self.create_history_tab()
        settings_tab = self.create_settings_tab()
        log_tab = self.create_log_tab()
        notifications_tab = self.create_notifications_tab()
        
        # Add tabs
        self.tab_widget.addTab(file_tab, "Encriptar/Desencriptar")
        self.tab_widget.addTab(history_tab, "Historial de Archivos")
        self.tab_widget.addTab(log_tab, "Registro de Seguridad")
        self.tab_widget.addTab(notifications_tab, "Notificaciones")
        self.tab_widget.addTab(settings_tab, "Configuración")
        
        # Add widgets to layout
        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.tab_widget)
        
        self.setCentralWidget(central_widget)
    
    # Control de temas
    def apply_theme(self, theme):
        self.current_theme = theme
        
        if theme == "Dark":
            self.setStyleSheet("""
                QMainWindow, QDialog, QTabWidget {
                    background-color: #172424;
                    color: #e0e0e0;
                }
                QTabWidget::pane { 
                    border: 1px solid #444444;
                    background-color: #1e2e2e;
                }
                QTabBar::tab {
                    background-color: #172424;
                    border: 1px solid #444444;
                    padding: 8px 16px;
                    margin-right: 2px;
                    color: #e0e0e0;
                }
                QTabBar::tab:selected {
                    background-color: #1e2e2e;
                    border-bottom-color: #1e2e2e;
                }
                QTabBar::tab:hover {
                    background-color: #2c3e3e;
                }
                QLabel {
                    color: #e0e0e0;
                }
                QLineEdit, QComboBox {
                    padding: 8px;
                    border: 1px solid #444444;
                    border-radius: 4px;
                    background-color: #253535;
                    color: #e0e0e0;
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
                QPushButton:pressed {
                    background-color: #1c6ea4;
                }
                QPushButton#encrypt_btn {
                    background-color: #2ecc71;
                }
                QPushButton#encrypt_btn:hover {
                    background-color: #27ae60;
                }
                QPushButton#decrypt_btn {
                    background-color: #e74c3c;
                }
                QPushButton#decrypt_btn:hover {
                    background-color: #c0392b;
                }
                QTableWidget {
                    border: 1px solid #444444;
                    gridline-color: #4a6868;
                    background-color: #253535;
                    color: #e0e0e0;
                }
                QTableWidget::item {
                    padding: 6px;
                    border-bottom: 1px solid #455555;
                }
                QTableWidget::item:selected {
                    background-color: #354545;
                    color: #ffffff;
                }
                QHeaderView {
                    background-color: #1a2a2a;
                }
                QHeaderView::section {
                    background-color: #1a2a2a;
                    padding: 8px;
                    border: 1px solid #4a6868;
                    font-weight: bold;
                    color: #e0e0e0;
                }
                QHeaderView::section:horizontal {
                    border-top: 1px solid #4a6868;
                }
                QHeaderView::section:vertical {
                    border-left: 1px solid #4a6868;
                }
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #444444;
                    border-radius: 4px;
                    margin-top: 12px;
                    padding-top: 16px;
                    color: #e0e0e0;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top left;
                    left: 8px;
                    padding: 0 5px;
                }
                QScrollBar:vertical {
                    border: none;
                    background: #253535;
                    width: 10px;
                    margin: 15px 0 15px 0;
                }
                QScrollBar::handle:vertical {
                    background: #4a6868;
                    min-height: 30px;
                    border-radius: 5px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #5a7878;
                }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                    border: none;
                    background: none;
                }
                QScrollBar:horizontal {
                    border: none;
                    background: #253535;
                    height: 10px;
                    margin: 0px 15px 0 15px;
                }
                QScrollBar::handle:horizontal {
                    background: #4a6868;
                    min-width: 30px;
                    border-radius: 5px;
                }
                QScrollBar::handle:horizontal:hover {
                    background: #5a7878;
                }
                QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                    border: none;
                    background: none;
                }
                QMenu {
                    background-color: #253535;
                    color: #e0e0e0;
                    border: 1px solid #4a6868;
                }
                QMenu::item:selected {
                    background-color: #354545;
                }
            """)
        else:  # Light theme
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #f5f5f5;
                }
                QTabWidget {
                    background-color: #f5f5f5;
                }
                QTabWidget::pane { 
                    border: 1px solid #cccccc;
                    background-color: white;
                }
                QTabBar::tab {
                    background-color: #e0e0e0;
                    border: 1px solid #cccccc;
                    padding: 8px 16px;
                    margin-right: 2px;
                }
                QTabBar::tab:selected {
                    background-color: white;
                    border-bottom-color: white;
                }
                QLabel {
                    color: #2c3e50;
                }
                QLineEdit {
                    padding: 8px;
                    border: 1px solid #bdc3c7;
                    border-radius: 4px;
                    background-color: white;
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
                QPushButton:pressed {
                    background-color: #1c6ea4;
                }
                QPushButton#encrypt_btn {
                    background-color: #2ecc71;
                }
                QPushButton#encrypt_btn:hover {
                    background-color: #27ae60;
                }
                QPushButton#decrypt_btn {
                    background-color: #e74c3c;
                }
                QPushButton#decrypt_btn:hover {
                    background-color: #c0392b;
                }
                QTableWidget {
                    border: 1px solid #ddd;
                    gridline-color: #ddd;
                    background-color: white;
                }
                QTableWidget::item {
                    padding: 6px;
                }
                QTableWidget::item:selected {
                    background-color: #cce8ff;
                    color: black;
                }
                QHeaderView::section {
                    background-color: #f0f0f0;
                    padding: 6px;
                    border: 1px solid #ddd;
                    font-weight: bold;
                }
                QGroupBox {
                    font-weight: bold;
                    border: 1px solid #cccccc;
                    border-radius: 4px;
                    margin-top: 12px;
                    padding-top: 16px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top left;
                    left: 8px;
                    padding: 0 5px;
                }
            """)
    
    def create_file_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Grupo de operaciones de archivo
        operations_group = QGroupBox("Operaciones de Archivo")
        operations_layout = QVBoxLayout()
        
        # Selección de archivo
        file_section = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Seleccione un archivo para encriptar o desencriptar")
        self.file_path_input.setReadOnly(True)
        
        browse_btn = QPushButton("Explorar")
        browse_btn.setFixedWidth(100)
        browse_btn.clicked.connect(self.browse_file)
        
        file_section.addWidget(self.file_path_input)
        file_section.addWidget(browse_btn)
        
        # Sección de contraseña
        password_section = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Ingrese contraseña para encriptar/desencriptar")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        password_section.addWidget(QLabel("Contraseña:"))
        password_section.addWidget(self.password_input)
        
        # Sección de botones
        buttons_section = QHBoxLayout()
        
        self.encrypt_btn = QPushButton("Encriptar Archivo")
        self.encrypt_btn.setObjectName("encrypt_btn")
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        
        self.decrypt_btn = QPushButton("Desencriptar Archivo")
        self.decrypt_btn.setObjectName("decrypt_btn")
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        
        buttons_section.addWidget(self.encrypt_btn)
        buttons_section.addWidget(self.decrypt_btn)
        
        # Agregar secciones a la disposición de operaciones
        operations_layout.addLayout(file_section)
        operations_layout.addLayout(password_section)
        operations_layout.addLayout(buttons_section)
        
        operations_group.setLayout(operations_layout)
        
        # Agregar a la disposición principal
        layout.addWidget(operations_group)
        layout.addStretch(1)
        
        tab.setLayout(layout)
        return tab
    
    def create_history_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Tabla de historial de archivos
        history_group = QGroupBox("Sus Archivos Encriptados")
        history_layout = QVBoxLayout()
        
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(5)
        self.files_table.setHorizontalHeaderLabels(["Nombre Original", "Tipo", "Tamaño", "Fecha de Encriptación", "Acciones"])
        
        # Configurar el comportamiento de la tabla
        self.files_table.setAlternatingRowColors(True)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.files_table.verticalHeader().setVisible(False)
        self.files_table.setColumnWidth(4, 150)
        self.files_table.verticalHeader().setDefaultSectionSize(45)
        
        # Configurar el tamaño de las columnas
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.files_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        
        history_layout.addWidget(self.files_table)
        history_group.setLayout(history_layout)
        
        # Botón de actualización
        refresh_btn = QPushButton("Actualizar Lista")
        refresh_btn.clicked.connect(self.load_user_files)
        
        layout.addWidget(history_group)
        layout.addWidget(refresh_btn)
        
        tab.setLayout(layout)
        return tab
    
    def create_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Configuración de seguridad
        security_group = QGroupBox("Configuración de Seguridad")
        security_layout = QFormLayout()
        
        self.security_level_combo = QComboBox()
        self.security_level_combo.addItems(["Baja", "Media", "Alta"])
        self.security_level_combo.setCurrentText("Media")
        self.security_level_combo.currentTextChanged.connect(self.change_security_level)
        
        security_layout.addRow("Nivel de Encriptación:", self.security_level_combo)
        
        security_info = QLabel("Baja: Más rápido pero menos seguro\nMedia: Balance entre rendimiento y seguridad\nAlta: Más seguro pero más lento")
        security_info.setStyleSheet("color: gray; font-style: italic;")
        security_layout.addRow("", security_info)
        
        security_group.setLayout(security_layout)
        
        # Configuración de interfaz
        interface_group = QGroupBox("Configuración de Interfaz")
        interface_layout = QFormLayout()
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Claro", "Oscuro", "Sistema"])
        self.theme_combo.setCurrentText("Claro")
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        
        interface_layout.addRow("Tema:", self.theme_combo)
        interface_group.setLayout(interface_layout)
        
        # Agregar a la disposición principal
        layout.addWidget(security_group)
        layout.addWidget(interface_group)
        layout.addStretch(1)
        
        # Botón de guardado
        save_btn = QPushButton("Guardar Configuración")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        tab.setLayout(layout)
        return tab
    
    def create_log_tab(self):
        """
        Crea la pestaña de registro de intentos de descifrado.
        
        Returns:
            QWidget: Widget con el contenido de la pestaña.
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Título y descripción
        title_label = QLabel("Registro de Seguridad - Intentos de Descifrado")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        description_label = QLabel(
            "Esta tabla muestra los intentos de descifrado de archivos, tanto exitosos como fallidos."
            " Los intentos fallidos pueden indicar actividad sospechosa o archivos corruptos."
        )
        description_label.setWordWrap(True)
        
        # Botón de actualizar
        refresh_btn = QPushButton("Actualizar Registro")
        refresh_btn.setFixedWidth(150)
        refresh_btn.clicked.connect(self.load_decryption_attempts)
        
        # Tabla de intentos
        self.attempts_table = QTableWidget()
        self.attempts_table.setColumnCount(7)
        self.attempts_table.setHorizontalHeaderLabels([
            "Fecha/Hora", "Archivo", "Estado", "Tipo de Error", 
            "Mensaje", "Equipo", "Dirección IP"
        ])
        
        # Ajustar propiedades de la tabla
        header = self.attempts_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Personalizar la apariencia de la tabla
        self.attempts_table.setAlternatingRowColors(True)
        self.attempts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.attempts_table.verticalHeader().setVisible(False)  # Ocultar cabecera vertical
        self.attempts_table.setShowGrid(True)  # Mostrar rejilla
        self.attempts_table.setGridStyle(Qt.PenStyle.SolidLine)  # Estilo de línea sólida para la rejilla
        
        # Añadir widgets al layout
        layout.addWidget(title_label)
        layout.addWidget(description_label)
        layout.addWidget(refresh_btn)
        layout.addWidget(self.attempts_table)
        
        # Cargar intentos por primera vez
        self.load_decryption_attempts()
        
        return tab
    
    def create_notifications_tab(self):
        """
        Crea la pestaña de notificaciones de seguridad.
        
        Returns:
            QWidget: Widget con el contenido de la pestaña.
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Título y descripción
        title_label = QLabel("Centro de Notificaciones")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        description_label = QLabel(
            "Aquí puede ver todas las notificaciones de seguridad generadas por el sistema."
        )
        description_label.setWordWrap(True)
        
        # Botón de actualizar
        refresh_btn = QPushButton("Actualizar Notificaciones")
        refresh_btn.setFixedWidth(180)
        refresh_btn.clicked.connect(self.load_notifications)
        
        # Tabla de notificaciones
        self.notifications_table = QTableWidget()
        self.notifications_table.setColumnCount(5)
        self.notifications_table.setHorizontalHeaderLabels([
            "Fecha/Hora", "Título", "Mensaje", "Severidad", "Estado"
        ])
        
        # Ajustar propiedades de la tabla
        header = self.notifications_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.notifications_table.setAlternatingRowColors(True)
        self.notifications_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        # Botón para marcar todas como leídas
        mark_all_read_btn = QPushButton("Marcar Todas como Leídas")
        mark_all_read_btn.clicked.connect(self.mark_all_notifications_read)
        
        # Añadir widgets al layout
        layout.addWidget(title_label)
        layout.addWidget(description_label)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(refresh_btn)
        button_layout.addStretch(1)
        button_layout.addWidget(mark_all_read_btn)
        
        layout.addLayout(button_layout)
        layout.addWidget(self.notifications_table)
        
        # Cargar notificaciones por primera vez
        self.load_notifications()
        
        return tab
    
    def load_user_files(self):
        # Obtener archivos encriptados del usuario de la base de datos
        files = self.db.get_encrypted_files_by_user(self.user_data['id'])
        
        # Limpiar la tabla
        self.files_table.setRowCount(0)
        
        # Rellenar la tabla
        for i, file in enumerate(files):
            self.files_table.insertRow(i)
            
            self.files_table.setItem(i, 0, QTableWidgetItem(file['original_filename']))
            self.files_table.setItem(i, 1, QTableWidgetItem(file['file_type']))
            self.files_table.setItem(i, 2, QTableWidgetItem(f"{file['file_size'] / 1024:.2f} KB"))
            self.files_table.setItem(i, 3, QTableWidgetItem(file['encryption_date']))
            
            # Crear botón de desencriptar y asignar el ID del archivo directamente
            decrypt_btn = QPushButton("Desencriptar")
            decrypt_btn.clicked.connect(lambda checked=False, file_id=file['id']: self.decrypt_from_history(file_id))
            
            self.files_table.setCellWidget(i, 4, decrypt_btn)
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar Archivo", "", "Todos los Archivos (*)")
        if file_path:
            self.file_path_input.setText(file_path)
    
    def encrypt_file(self):
        file_path = self.file_path_input.text()
        password = self.password_input.text()
        
        if not file_path:
            QMessageBox.warning(self, "Advertencia", "Por favor seleccione un archivo para encriptar.")
            return
        
        if not password:
            QMessageBox.warning(self, "Advertencia", "Por favor ingrese una contraseña para la encriptación.")
            return
        
        try:
            # Encriptar el archivo
            result = self.crypto_manager.encrypt_file(file_path, password)
            
            # Almacenar la información del archivo en la base de datos
            self.db.add_encrypted_file(
                self.user_data['id'],
                result['original_filename'],
                result['encrypted_filename'],
                result['file_type'],
                result['file_size'],
                result['nonce'],
                result['tag']
            )
            
            # Limpiar entradas
            self.file_path_input.clear()
            self.password_input.clear()
            
            # Actualizar la lista de archivos
            self.load_user_files()
            
            QMessageBox.information(self, "Éxito", f"Archivo encriptado exitosamente y guardado como {result['encrypted_filename']}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error de Encriptación", str(e))
    
    def decrypt_file(self):
        file_path = self.file_path_input.text()
        password = self.password_input.text()
        
        if not file_path:
            QMessageBox.warning(self, "Advertencia", "Por favor seleccione un archivo para desencriptar.")
            return
        
        if not password:
            QMessageBox.warning(self, "Advertencia", "Por favor ingrese la contraseña de desencriptación.")
            return
        
        # Verificar si el archivo termina con .encrypted
        if not file_path.endswith('.encrypted'):
            QMessageBox.warning(self, "Advertencia", "El archivo seleccionado no parece ser un archivo encriptado. Los archivos encriptados deben tener la extensión .encrypted.")
            return
        
        # Derivar el nombre original del archivo
        original_name = os.path.basename(file_path)[:-10]  # Eliminar .encrypted
        
        # Preguntar por la ubicación de salida
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar Archivo Desencriptado", original_name, "Todos los Archivos (*)"
        )
        
        if not output_path:
            return
        
        # Encontrar el archivo en la base de datos para obtener el nonce y el tag
        file_info = None
        files = self.db.get_encrypted_files_by_user(self.user_data['id'])
        
        for file in files:
            if file['encrypted_filename'] == os.path.basename(file_path):
                file_info = file
                break
        
        if not file_info:
            QMessageBox.warning(self, "Advertencia", "Este archivo no aparece en su base de datos de archivos encriptados. Es posible que no tenga las credenciales correctas para desencriptarlo.")
            return
        
        try:
            # Desencriptar el archivo
            result = self.crypto_manager.decrypt_file(
                file_path,
                password,
                output_path,
                file_info['nonce'],
                file_info['tag']
            )
            
            # Registrar el intento
            import socket
            hostname = socket.gethostname()
            
            self.db.log_decryption_attempt(
                user_id=self.user_data['id'],
                file_id=file_info['id'],
                hostname=hostname,
                success=result['success'],
                error_type=result.get('error_type'),
                error_message=result.get('message')
            )
            
            if result['success']:
                self.file_path_input.clear()
                self.password_input.clear()
                QMessageBox.information(self, "Éxito", f"Archivo desencriptado exitosamente y guardado en {output_path}")
            else:
                # Mostrar mensaje de error específico
                if result.get('error_type') == 'authentication_failed':
                    QMessageBox.critical(self, "Error de Autenticación", 
                        "El archivo parece haber sido modificado o corrompido. No se puede verificar su autenticidad.\n\n"
                        "Esto puede ocurrir si el archivo fue alterado después de ser cifrado, lo que es una "
                        "característica de seguridad del sistema de cifrado utilizado (AES-GCM).")
                else:
                    QMessageBox.critical(self, "Error de Desencriptación", result.get('message'))
                
                # Verificar si se deben mostrar alertas por intentos fallidos
                if not result['success']:
                    self.notification_manager.check_failed_attempts(self.user_data['id'])
                    # Actualizamos la tabla de intentos
                    self.load_decryption_attempts()
            
        except Exception as e:
            QMessageBox.critical(self, "Error de Desencriptación", str(e))
    
    def decrypt_from_history(self, file_id):
        file_info = self.db.get_file_info(file_id)
        
        if not file_info:
            QMessageBox.warning(self, "Advertencia", "Información del archivo no encontrada.")
            return
        
        # Preguntar por la contraseña
        password, ok = QInputDialog.getText(
            self, "Contraseña de Desencriptación", "Ingrese la contraseña para desencriptar el archivo:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            return
        
        # Encontrar el archivo encriptado
        encrypted_file_path = os.path.join('data', file_info['encrypted_filename'])
        
        if not os.path.exists(encrypted_file_path):
            QMessageBox.warning(self, "Advertencia", f"Archivo encriptado no encontrado en {encrypted_file_path}. Por favor verifique la ubicación del archivo.")
            return
        
        # Preguntar por la ubicación de salida
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar Archivo Desencriptado", file_info['original_filename'], "Todos los Archivos (*)"
        )
        
        if not output_path:
            return
        
        try:
            # Desencriptar el archivo
            result = self.crypto_manager.decrypt_file(
                encrypted_file_path,
                password,
                output_path,
                file_info['nonce'],
                file_info['tag']
            )
            
            # Registrar el intento
            import socket
            hostname = socket.gethostname()
            
            self.db.log_decryption_attempt(
                user_id=self.user_data['id'],
                file_id=file_info['id'],
                hostname=hostname,
                success=result['success'],
                error_type=result.get('error_type'),
                error_message=result.get('message')
            )
            
            if result['success']:
                QMessageBox.information(self, "Éxito", f"Archivo desencriptado exitosamente y guardado en {output_path}")
            else:
                # Mostrar mensaje de error específico
                if result.get('error_type') == 'authentication_failed':
                    QMessageBox.critical(self, "Error de Autenticación", 
                        "El archivo parece haber sido modificado o corrompido. No se puede verificar su autenticidad.\n\n"
                        "Esto puede ocurrir si el archivo fue alterado después de ser cifrado, lo que es una "
                        "característica de seguridad del sistema de cifrado utilizado (AES-GCM).")
                else:
                    QMessageBox.critical(self, "Error de Desencriptación", result.get('message'))
                
                # Verificar si se deben mostrar alertas por intentos fallidos
                if not result['success']:
                    self.notification_manager.check_failed_attempts(self.user_data['id'])
                    # Actualizamos la tabla de intentos
                    self.load_decryption_attempts()
            
        except Exception as e:
            QMessageBox.critical(self, "Error de Desencriptación", str(e))
    
    def change_security_level(self, level):
        level_map = {
            "Baja": "low",
            "Media": "medium",
            "Alta": "high"
        }
        self.crypto_manager.set_security_level(level_map.get(level, "medium"))
    
    def change_theme(self, theme):
        theme_map = {
            "Claro": "Light",
            "Oscuro": "Dark",
            "Sistema": "System"
        }
        
        selected_theme = theme_map.get(theme, "Light")
        if selected_theme == "System":
            # Aquí se podría implementar la detección del tema del sistema
            # Por ahora solo usaremos el tema oscuro por defecto
            selected_theme = "Dark"
            
        self.apply_theme(selected_theme)
    
    def save_settings(self):
        QMessageBox.information(self, "Configuración Guardada", "Su configuración ha sido guardada exitosamente.")
    
    def logout(self):
        reply = QMessageBox.question(self, "Cerrar Sesión", "¿Está seguro de que desea cerrar sesión?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.close()
            # Signal to reopen login window would go here 
    
    def load_decryption_attempts(self):
        """
        Carga y muestra los intentos de descifrado en la tabla.
        """
        # Obtener los intentos del usuario actual
        attempts = self.db.get_decryption_attempts(user_id=self.user_data['id'])
        
        # Limpiar tabla
        self.attempts_table.setRowCount(0)
        
        # Llenar tabla con datos
        for attempt in attempts:
            row_position = self.attempts_table.rowCount()
            self.attempts_table.insertRow(row_position)
            
            # Formatear timestamp
            timestamp = datetime.strptime(attempt['timestamp'], "%Y-%m-%d %H:%M:%S")
            formatted_timestamp = timestamp.strftime("%d/%m/%Y %H:%M:%S")
            
            # Estado como texto
            status = "Exitoso" if attempt['success'] else "Fallido"
            
            # Llenar celdas
            self.attempts_table.setItem(row_position, 0, QTableWidgetItem(formatted_timestamp))
            self.attempts_table.setItem(row_position, 1, QTableWidgetItem(attempt['original_filename']))
            
            # Crear item para el estado y darle color de fondo según éxito o fallo
            status_item = QTableWidgetItem(status)
            if attempt['success']:
                status_item.setBackground(Qt.GlobalColor.green)
                status_item.setForeground(Qt.GlobalColor.black)
            else:
                status_item.setBackground(Qt.GlobalColor.red)
                status_item.setForeground(Qt.GlobalColor.white)
            
            self.attempts_table.setItem(row_position, 2, status_item)
            
            error_type_item = QTableWidgetItem(attempt['error_type'] or "")
            if attempt['error_type']:
                error_type_item.setForeground(Qt.GlobalColor.red)
            self.attempts_table.setItem(row_position, 3, error_type_item)
            
            error_msg_item = QTableWidgetItem(attempt['error_message'] or "")
            if attempt['error_message']:
                error_msg_item.setForeground(Qt.GlobalColor.red)
            self.attempts_table.setItem(row_position, 4, error_msg_item)
            
            self.attempts_table.setItem(row_position, 5, QTableWidgetItem(attempt['hostname'] or ""))
            self.attempts_table.setItem(row_position, 6, QTableWidgetItem(attempt['ip_address'] or ""))
            
            # Configurar fuente
            for col in range(7):
                item = self.attempts_table.item(row_position, col)
                if item:
                    font = QFont()
                    font.setPointSize(9)
                    item.setFont(font)
    
    def check_notifications(self):
        """
        Verifica y muestra notificaciones pendientes.
        """
        unread_notifications = self.notification_manager.get_notifications(
            self.user_data['id'], unread_only=True
        )
        
        if unread_notifications:
            # Mostrar la primera notificación no leída
            notification = unread_notifications[0]
            self.notification_manager.show_notification_dialog(self, notification)
            self.notification_manager.mark_as_read(notification['id']) 
    
    def load_notifications(self):
        """
        Carga y muestra las notificaciones en la tabla.
        """
        # Obtener las notificaciones del usuario actual
        notifications = self.notification_manager.get_notifications(self.user_data['id'])
        
        # Limpiar tabla
        self.notifications_table.setRowCount(0)
        
        # Llenar tabla con datos
        for notification in notifications:
            row_position = self.notifications_table.rowCount()
            self.notifications_table.insertRow(row_position)
            
            # Formatear timestamp
            timestamp = datetime.strptime(notification['timestamp'], "%Y-%m-%d %H:%M:%S")
            formatted_timestamp = timestamp.strftime("%d/%m/%Y %H:%M:%S")
            
            # Estado como texto
            read_status = "Leída" if notification['read'] else "No leída"
            
            # Severidad como texto
            severity_map = {
                "low": "Baja",
                "medium": "Media",
                "high": "Alta"
            }
            severity = severity_map.get(notification['severity'], "Media")
            
            # Llenar celdas
            self.notifications_table.setItem(row_position, 0, QTableWidgetItem(formatted_timestamp))
            self.notifications_table.setItem(row_position, 1, QTableWidgetItem(notification['title']))
            self.notifications_table.setItem(row_position, 2, QTableWidgetItem(notification['message']))
            self.notifications_table.setItem(row_position, 3, QTableWidgetItem(severity))
            self.notifications_table.setItem(row_position, 4, QTableWidgetItem(read_status))
            
            # Colorear según la severidad
            if notification['severity'] == 'high':
                self.notifications_table.item(row_position, 3).setBackground(Qt.GlobalColor.red)
            elif notification['severity'] == 'medium':
                self.notifications_table.item(row_position, 3).setBackground(Qt.GlobalColor.yellow)
            else:
                self.notifications_table.item(row_position, 3).setBackground(Qt.GlobalColor.green)
                
            # Colorear según estado de lectura
            if not notification['read']:
                self.notifications_table.item(row_position, 4).setBackground(Qt.GlobalColor.cyan)
    
    def mark_all_notifications_read(self):
        """
        Marca todas las notificaciones del usuario como leídas.
        """
        notifications = self.notification_manager.get_notifications(self.user_data['id'], unread_only=True)
        
        for notification in notifications:
            self.notification_manager.mark_as_read(notification['id'])
            
        # Actualizar la vista
        self.load_notifications() 