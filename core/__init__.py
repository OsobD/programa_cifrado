"""
Módulo core para la función de cifrado y descifrado.

Este módulo da una implementación segura de operaciones de cifrado 
y descifrado utilizando algoritmos criptográficos estándar de la industria.

Clases:
    CryptoManager: Administra el cifrado/descifrado de archivos con niveles 
                   de seguridad configurables
"""

from .crypto import CryptoManager

__all__ = ['CryptoManager'] 