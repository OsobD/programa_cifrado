import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon

from ui.login import LoginDialog
from ui.main_window import MainWindow
from utils.database import Database
from utils.auth import Auth
from utils.notifications import NotificationManager
from core.crypto import CryptoManager

def main():
    # Crear aplicación
    app = QApplication(sys.argv)
    app.setApplicationName("OsobCrypter")
    app.setWindowIcon(QIcon("Logo Of Rojo.png"))
    
    # Asegurar que existan los directorios de datos
    os.makedirs('data', exist_ok=True)
    
    # Inicializar componentes
    db = Database()
    auth = Auth(db)
    crypto = CryptoManager()
    
    # Mostrar diálogo de inicio de sesión
    login_dialog = LoginDialog(auth)
    result = login_dialog.exec_()
    
    # Si el inicio de sesión es exitoso, mostrar ventana principal
    if result == LoginDialog.DialogCode.Accepted:
        user_data = login_dialog.get_user_data()
        main_window = MainWindow(crypto, db, user_data)
        main_window.show()
        sys.exit(app.exec_())

if __name__ == "__main__":
    main() 