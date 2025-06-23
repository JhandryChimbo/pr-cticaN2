# Ejercicio 3: Cifrado AES con clave de 256 bits y modo CFB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
import os

KEY_FILE = 'aes_key.bin'
IV_FILE = 'aes_iv.bin'

def generar_clave_aes():
    clave = urandom(32)
    iv = urandom(16)
    with open(KEY_FILE, 'wb') as f:
        f.write(clave)
    with open(IV_FILE, 'wb') as f:
        f.write(iv)
    os.chmod(KEY_FILE, 0o600)
    os.chmod(IV_FILE, 0o600)
    print(f"Clave AES generada y guardada en {KEY_FILE}: {clave.hex()}")
    print(f"IV generado y guardado en {IV_FILE}: {iv.hex()}")
    return clave, iv

def cargar_clave_aes():
    with open(KEY_FILE, 'rb') as f:
        clave = f.read()
    with open(IV_FILE, 'rb') as f:
        iv = f.read()
    print(f"Clave AES cargada de {KEY_FILE}: {clave.hex()}")
    print(f"IV cargado de {IV_FILE}: {iv.hex()}")
    return clave, iv

def cifrar_mensaje(clave, iv, mensaje):
    cipher = Cipher(algorithms.AES(clave), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(mensaje.encode()) + encryptor.finalize()

def descifrar_mensaje(clave, iv, cifrado):
    cipher = Cipher(algorithms.AES(clave), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(cifrado) + decryptor.finalize()).decode()

clave, iv = generar_clave_aes()
clave, iv = cargar_clave_aes()
cifrado = cifrar_mensaje(clave, iv, "Jhandry Santiago Chimbo Rivera")
print("Mensaje cifrado:", cifrado.hex())
print("Descifrado:", descifrar_mensaje(clave, iv, cifrado))
