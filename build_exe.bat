@echo off
echo Creando OsobCrypter.exe...

echo 1. Verificando entorno virtual...
if not exist .venv (
    echo Creando entorno virtual...
    python -m venv .venv
)

echo 2. Activando entorno virtual...
call .venv\Scripts\activate.bat

echo 3. Instalando dependencias...
pip install -r requirements.txt

echo 3.1. Asegurando que PyInstaller y Pillow estén instalados...
pip install pyinstaller pillow

echo 4. Ejecutando compilacion...
python build.py

echo 5. Proceso completado!
echo El ejecutable OsobCrypter.exe se encuentra en la carpeta 'dist'.
echo.
pause 