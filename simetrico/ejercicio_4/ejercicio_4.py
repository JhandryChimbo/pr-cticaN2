from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode
from os import urandom

from cryptography.hazmat.backends import default_backend

# Derivar clave con PBKDF2
def derivar_clave(password, salt, iteraciones=100_000):
    print(f"Derivando clave con password='{password}', salt={b64encode(salt).decode()}, iteraciones={iteraciones}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iteraciones,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Cifrar y descifrar
def aes_pbkdf2(password, mensaje):
    salt = urandom(16)
    iv = urandom(16)
    clave = derivar_clave(password, salt)
    print(f"Clave derivada: {b64encode(clave).decode()}")
    cipher = Cipher(algorithms.AES(clave), modes.CFB(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(mensaje.encode()) + encryptor.finalize()

    # Descifrado
    clave2 = derivar_clave(password, salt)
    cipher2 = Cipher(algorithms.AES(clave2), modes.CFB(iv))
    decryptor = cipher2.decryptor()
    descifrado = decryptor.update(cifrado) + decryptor.finalize()

    return cifrado, descifrado.decode()

c, d = aes_pbkdf2("admin123@", "Jhandry Santiago Chimbo Rivera")
print("Cifrado:", b64encode(c))
print("Descifrado:", d)
