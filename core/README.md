# Módulo Core - Sistema de Cifrado Seguro

Este módulo implementa funcionalidades de cifrado y descifrado de archivos utilizando algoritmos criptográficos de estándar industrial.

## Características

- Cifrado de archivos utilizando AES-256-GCM, un algoritmo de cifrado autenticado
- Derivación de claves con Argon2id, resistente a ataques por hardware especializado
- Niveles de seguridad configurables (bajo, medio, alto)
- Gestión segura de nonces, sales y etiquetas de autenticación

## Componentes

El módulo contiene una clase principal:

### CryptoManager

Esta clase proporciona métodos para cifrar y descifrar archivos con diferentes niveles de seguridad. Los métodos principales son:

- `encrypt_file`: Cifra un archivo y devuelve metadatos necesarios para el descifrado
- `decrypt_file`: Descifra un archivo previamente cifrado
- `set_security_level`: Configura los parámetros de seguridad según un nivel preestablecido

## Uso Básico

```python
from core import CryptoManager

# Crear un administrador criptográfico con nivel de seguridad medio (predeterminado)
crypto = CryptoManager()

# Para nivel alto de seguridad
# crypto = CryptoManager(security_level="high")

# Cifrar un archivo
metadata = crypto.encrypt_file("documento.pdf", "contraseña_segura")

# Guardar los metadatos en una base de datos
# ... código para guardar metadata['nonce'] y metadata['tag'] ...

# Descifrar el archivo
crypto.decrypt_file(
    metadata['encrypted_file_path'],
    "contraseña_segura",
    "documento_descifrado.pdf",
    metadata['nonce'],
    metadata['tag']
)
```

## Parámetros de Seguridad

| Nivel | Tiempo | Memoria | Paralelismo | Recomendado para |
|-------|--------|---------|-------------|------------------|
| bajo  | 2      | 32 MB   | 2           | Archivos pequeños o dispositivos con recursos limitados |
| medio | 3      | 64 MB   | 4           | Uso general |
| alto  | 4      | 128 MB  | 8           | Datos sensibles |

## Notas de Seguridad

- Las claves nunca se almacenan, solo se derivan de la contraseña cuando es necesario
- La sal se almacena junto con el archivo cifrado para permitir la derivación de la misma clave
- El nonce (número utilizado una sola vez) debe almacenarse de forma segura
- La etiqueta de autenticación debe almacenarse de forma segura y verificarse durante el descifrado

## Dependencias

- cryptography
- argon2-cffi 