import os
import sys
import shutil
import PyInstaller.__main__

# Asegurarse de que la carpeta dist y build no existan
if os.path.exists("dist"):
    shutil.rmtree("dist")
if os.path.exists("build"):
    shutil.rmtree("build")

# Crear carpeta para recursos temporales
if not os.path.exists("temp_resources"):
    os.makedirs("temp_resources")

# Copiar los recursos necesarios a una carpeta temporal
shutil.copy("Logo Of Rojo.png", "temp_resources/")

# Definir argumentos para PyInstaller
pyinstaller_args = [
    'main.py',
    '--name=OsobCrypter',
    '--noconsole',
    '--onefile',
    '--clean',
    '--add-data=Logo Of Rojo.png;.',
    '--hidden-import=PyQt5',
    '--hidden-import=PyQt5.QtCore',
    '--hidden-import=PyQt5.QtGui',
    '--hidden-import=PyQt5.QtWidgets',
    '--hidden-import=cryptography',
    '--hidden-import=argon2-cffi',
]

# Intentar compilar con icono
try:
    print("Intentando compilar con icono...")
    # Añadir el argumento del icono
    with_icon_args = pyinstaller_args + ['--icon=Logo Of Rojo.png']
    PyInstaller.__main__.run(with_icon_args)
except Exception as e:
    print(f"Error al compilar con icono: {e}")
    print("Intentando compilar sin icono...")
    
    # Limpiar directorios para un nuevo intento
    if os.path.exists("dist"):
        shutil.rmtree("dist")
    if os.path.exists("build"):
        shutil.rmtree("build")
    if os.path.exists("OsobCrypter.spec"):
        os.remove("OsobCrypter.spec")
    
    # Ejecutar PyInstaller sin el icono
    PyInstaller.__main__.run(pyinstaller_args)

# Crear la carpeta de datos en el directorio dist
os.makedirs("dist/data", exist_ok=True)

# Limpiar recursos temporales
if os.path.exists("temp_resources"):
    shutil.rmtree("temp_resources")

print("Compilación completada. El ejecutable se encuentra en la carpeta 'dist'.") 