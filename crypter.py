import argparse
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from getpass import getpass
import secrets

# Derivar clave a partir de la contraseña
def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Función para encriptar
def encrypt_file(file_path):
    # Generar una contraseña segura
    password = secrets.token_urlsafe(16)
    print(f"Contraseña generada: {password}")
    password_bytes = password.encode()

    # Leer el contenido del archivo
    with open(file_path, 'rb') as file:
        data = file.read()

    # Generar una sal y derivar una clave a partir de la contraseña
    salt = os.urandom(16)
    key = derive_key(password_bytes, salt)

    # Cifrar los datos con AES en modo CBC
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Añadir padding al contenido para que sea múltiplo de 16 bytes
    padding_length = 16 - len(data) % 16
    data += bytes([padding_length]) * padding_length

    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Guardar el archivo encriptado junto con la sal y el IV
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(salt + iv + encrypted_data)

# Función para desencriptar
def decrypt_file(file_path):
    password = getpass("Introduce la contraseña para desencriptar: ").encode()

    # Leer el archivo encriptado
    with open(file_path, 'rb') as enc_file:
        salt = enc_file.read(16)
        iv = enc_file.read(16)
        encrypted_data = enc_file.read()

    # Derivar la clave con la contraseña proporcionada
    key = derive_key(password, salt)

    # Descifrar los datos
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Eliminar el padding
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]

    # Guardar el contenido desencriptado en un nuevo archivo
    output_file = file_path.replace('.enc', '_decrypted.txt')
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)
    print(f"Archivo desencriptado y guardado como {output_file}")

# Argumentos de la línea de comandos
parser = argparse.ArgumentParser(description="Encriptar o desencriptar un archivo.")
parser.add_argument('-e', '--encrypt', help="Ruta del archivo a encriptar")
parser.add_argument('-d', '--decrypt', help="Ruta del archivo a desencriptar")
args = parser.parse_args()

if args.encrypt:
    encrypt_file(args.encrypt)
elif args.decrypt:
    decrypt_file(args.decrypt)
else:
    print("Debes proporcionar una opción válida: -e para encriptar o -d para desencriptar")
