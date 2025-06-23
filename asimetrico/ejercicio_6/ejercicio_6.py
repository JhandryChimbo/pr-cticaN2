from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
print("Clave privada RSA generada.")

password = getpass("Introduce una contraseña para proteger la clave privada: ").encode()

clave_privada_encriptada = clave_privada.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password)
)
print("Clave privada cifrada y lista para guardar.")

with open("clave_privada_segura.pem", "wb") as f:
    f.write(clave_privada_encriptada)

with open("clave_privada_segura.pem", "rb") as f:
    clave_privada_cargada = serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())
print("Clave privada leída y descifrada correctamente desde el archivo.")

mensaje = b"Evangelion 3.0 es la mejor"
clave_publica = clave_privada_cargada.public_key()
cifrado = clave_publica.encrypt(
    mensaje,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
descifrado = clave_privada_cargada.decrypt(
    cifrado,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

print("Descifrado exitoso:", descifrado.decode())
