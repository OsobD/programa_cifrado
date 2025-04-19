import os
import json
from datetime import datetime, timedelta
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import QTimer

class NotificationManager:
    """
    Gestor de notificaciones de seguridad para la aplicación.
    
    Esta clase maneja la generación y mostrado de notificaciones para eventos 
    de seguridad, como intentos de descifrado fallidos.
    
    Atributos:
        notifications_path (str): Ruta al archivo donde se guardan las notificaciones
        threshold (int): Número de intentos fallidos para generar una alerta
        time_window (int): Ventana de tiempo en horas para considerar los intentos
    """
    
    def __init__(self, db, notifications_path='data/notifications.json', threshold=3, time_window=24):
        """
        Inicializa el gestor de notificaciones.
        
        Args:
            db: Objeto Database para consultar intentos de descifrado
            notifications_path (str): Ruta al archivo de notificaciones
            threshold (int): Número de intentos fallidos para generar una alerta
            time_window (int): Ventana de tiempo en horas para considerar los intentos
        """
        self.db = db
        self.notifications_path = notifications_path
        self.threshold = threshold
        self.time_window = time_window
        self.ensure_notification_file()
        
    def ensure_notification_file(self):
        """Asegura que el archivo de notificaciones exista"""
        os.makedirs(os.path.dirname(self.notifications_path), exist_ok=True)
        
        if not os.path.exists(self.notifications_path):
            with open(self.notifications_path, 'w') as f:
                json.dump([], f)
    
    def check_failed_attempts(self, user_id):
        """
        Verifica si hay una cantidad sospechosa de intentos fallidos de descifrado.
        
        Args:
            user_id (int): ID del usuario para verificar
            
        Returns:
            bool: True si se detectaron demasiados intentos fallidos, False en caso contrario
        """
        # Obtener todos los intentos de descifrado
        attempts = self.db.get_decryption_attempts(user_id=user_id)
        
        # Filtrar intentos fallidos en la ventana de tiempo
        now = datetime.now()
        time_threshold = now - timedelta(hours=self.time_window)
        
        recent_failed_attempts = [
            attempt for attempt in attempts
            if not attempt['success'] and 
               datetime.strptime(attempt['timestamp'], "%Y-%m-%d %H:%M:%S") > time_threshold
        ]
        
        # Verificar si superan el umbral
        if len(recent_failed_attempts) >= self.threshold:
            # Generar notificación
            self.add_notification(
                user_id=user_id,
                title="Alerta de Seguridad",
                message=f"Se han detectado {len(recent_failed_attempts)} intentos fallidos de descifrado en las últimas {self.time_window} horas.",
                severity="high",
                attempts=recent_failed_attempts
            )
            return True
            
        return False
    
    def add_notification(self, user_id, title, message, severity="medium", attempts=None):
        """
        Añade una nueva notificación al registro.
        
        Args:
            user_id (int): ID del usuario al que pertenece la notificación
            title (str): Título de la notificación
            message (str): Mensaje detallado
            severity (str): Nivel de severidad ("low", "medium", "high")
            attempts (list, opcional): Lista de intentos relacionados con la notificación
        """
        with open(self.notifications_path, 'r') as f:
            notifications = json.load(f)
        
        notification = {
            "id": len(notifications) + 1,
            "user_id": user_id,
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "read": False
        }
        
        if attempts:
            notification["attempts"] = [attempt['id'] for attempt in attempts]
            
        notifications.append(notification)
        
        with open(self.notifications_path, 'w') as f:
            json.dump(notifications, f, indent=2)
    
    def get_notifications(self, user_id, unread_only=False):
        """
        Obtiene las notificaciones para un usuario.
        
        Args:
            user_id (int): ID del usuario
            unread_only (bool): Si True, solo devuelve notificaciones no leídas
            
        Returns:
            list: Lista de notificaciones
        """
        with open(self.notifications_path, 'r') as f:
            all_notifications = json.load(f)
        
        # Filtrar por usuario
        user_notifications = [n for n in all_notifications if n['user_id'] == user_id]
        
        # Filtrar por estado de lectura si es necesario
        if unread_only:
            user_notifications = [n for n in user_notifications if not n['read']]
            
        return user_notifications
    
    def mark_as_read(self, notification_id):
        """
        Marca una notificación como leída.
        
        Args:
            notification_id (int): ID de la notificación a marcar
            
        Returns:
            bool: True si se encontró y modificó la notificación, False en caso contrario
        """
        with open(self.notifications_path, 'r') as f:
            notifications = json.load(f)
        
        for notification in notifications:
            if notification['id'] == notification_id:
                notification['read'] = True
                
                with open(self.notifications_path, 'w') as f:
                    json.dump(notifications, f, indent=2)
                    
                return True
                
        return False
        
    def show_notification_dialog(self, parent, notification):
        """
        Muestra un diálogo con la notificación.
        
        Args:
            parent: Widget padre para el diálogo
            notification (dict): Datos de la notificación a mostrar
        """
        icon = QMessageBox.Icon.Warning
        if notification['severity'] == 'high':
            icon = QMessageBox.Icon.Critical
        elif notification['severity'] == 'low':
            icon = QMessageBox.Icon.Information
            
        msgbox = QMessageBox(parent)
        msgbox.setWindowTitle(notification['title'])
        msgbox.setText(notification['message'])
        msgbox.setIcon(icon)
        
        # Añadir detalles sobre la fecha
        timestamp = datetime.strptime(notification['timestamp'], "%Y-%m-%d %H:%M:%S")
        formatted_time = timestamp.strftime("%d/%m/%Y %H:%M:%S")
        msgbox.setInformativeText(f"Alerta generada el {formatted_time}")
        
        msgbox.exec_() 