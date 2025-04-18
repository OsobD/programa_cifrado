# Encriptador de Archivos Seguro

Una aplicación segura de encriptación de archivos construida con Python y PyQt5. Esta aplicación le permite encriptar y desencriptar archivos utilizando encriptación AES-256-GCM con derivación de claves Argon2.

## Características

- Encriptar y desencriptar archivos de cualquier tipo (texto, imágenes, documentos, etc.)
- Encriptación AES-256-GCM para encriptación autenticada
- Argon2 para derivación segura de claves basada en contraseñas
- Sistema de autenticación de usuarios con diferentes niveles de seguridad
- Seguimiento del historial de archivos encriptados
- Base de datos SQLite para almacenamiento de metadatos (no se almacenan claves)
- Interfaz de usuario moderna y amigable
- Modo oscuro personalizado con el tono #172424

## Requisitos

- Python 3.6+
- PyQt5
- cryptography
- argon2-cffi
- sqlite3 (incluido en la biblioteca estándar de Python)

## Instalación

1. Clone el repositorio:

```
git clone https://github.com/sunombre/encriptador-archivos-seguro.git
cd encriptador-archivos-seguro
```

2. Cree un entorno virtual (opcional pero recomendado):

```
python -m venv venv
```

3. Active el entorno virtual:

- En Windows:
```
venv\Scripts\activate
```

- En macOS/Linux:
```
source venv/bin/activate
```

4. Instale los paquetes requeridos:

```
pip install -r requirements.txt
```

## Uso

1. Ejecute la aplicación:

```
python main.py
```

2. Registre una nueva cuenta de usuario o inicie sesión con credenciales existentes.

3. Use la pestaña "Encriptar/Desencriptar" para:
   - Seleccionar archivos para encriptar/desencriptar
   - Ingresar una contraseña fuerte
   - Encriptar o desencriptar archivos

4. Vea su historial de archivos encriptados en la pestaña "Historial de Archivos".

5. Configure los ajustes de seguridad en la pestaña "Configuración".

## Notas de Seguridad

- La aplicación utiliza encriptación estándar de la industria (AES-256-GCM) y derivación de claves (Argon2).
- Las contraseñas nunca se almacenan; solo se guardan los hashes de contraseñas en la base de datos.
- Las claves de encriptación se derivan de contraseñas utilizando Argon2, una función resistente a ataques de fuerza bruta.
- Los archivos encriptados incluyen etiquetas de autenticación para garantizar la integridad.
- Todas las operaciones criptográficas utilizan las bibliotecas bien probadas `cryptography` y `argon2-cffi`.

## Estructura del Proyecto

- `main.py`: Punto de entrada de la aplicación
- `ui/`: Componentes de la interfaz de usuario
- `core/`: Lógica de encriptación
- `utils/`: Utilidades de base de datos y autenticación
- `data/`: Almacenamiento para archivos encriptados y base de datos

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - consulte el archivo LICENSE para más detalles. 