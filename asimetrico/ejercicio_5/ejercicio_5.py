from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

clave_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
clave_publica = clave_rsa.public_key()

public_pem = clave_publica.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("clave_publica.pem", "wb") as f:
    f.write(public_pem)
    print("Clave pública guardada en 'clave_publica.pem'")

with open("clave_publica.pem", "rb") as f:
    clave_publica_importada = serialization.load_pem_public_key(f.read(), backend=default_backend())
    print("Clave pública importada correctamente")

mensaje = b"Mensaje para cifrar con clave importada"
cifrado = clave_publica_importada.encrypt(
    mensaje,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

descifrado = clave_rsa.decrypt(
    cifrado,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

print("Mensaje descifrado:", descifrado.decode())
