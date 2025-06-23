from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from os import urandom

bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bob_public_key = bob_private_key.public_key()

mensaje = b"Mensaje para Bob, pasar la materia"
clave_simetrica = urandom(32)
iv = urandom(16)
print("Clave AES generada por Alice:", clave_simetrica.hex())
print("IV generado por Alice:", iv.hex())

cipher = Cipher(algorithms.AES(clave_simetrica), modes.CFB(iv))
cifrado_mensaje = cipher.encryptor().update(mensaje) + cipher.encryptor().finalize()
print("Mensaje cifrado con AES:", cifrado_mensaje.hex())

clave_simetrica_cifrada = bob_public_key.encrypt(
    clave_simetrica,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

clave_simetrica_descifrada = bob_private_key.decrypt(
    clave_simetrica_cifrada,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print("Clave AES descifrada por Bob:", clave_simetrica_descifrada.hex())

cipher2 = Cipher(algorithms.AES(clave_simetrica_descifrada), modes.CFB(iv))
mensaje_descifrado = cipher2.decryptor().update(cifrado_mensaje) + cipher2.decryptor().finalize()
print("Mensaje descifrado por Bob:", mensaje_descifrado.decode())
