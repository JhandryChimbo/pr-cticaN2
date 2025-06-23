from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from os import urandom

bob_private_key = ec.generate_private_key(ec.SECP256R1())
bob_public_key = bob_private_key.public_key()

alice_private_key = ec.generate_private_key(ec.SECP256R1())
alice_public_key = alice_private_key.public_key()

shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)

derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdh", backend=default_backend()).derive(shared_key)

iv = urandom(16)
mensaje = b"Pasar la materia (ECIES simulado)"
cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
cifrado = cipher.encryptor().update(mensaje) + cipher.encryptor().finalize()

print("Mensaje cifrado (hex):", cifrado.hex())
print("IV utilizado (hex):", iv.hex())          

shared_key_bob = bob_private_key.exchange(ec.ECDH(), alice_public_key)
derived_key_bob = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecdh", backend=default_backend()).derive(shared_key_bob)

cipher_bob = Cipher(algorithms.AES(derived_key_bob), modes.CFB(iv))
descifrado = cipher_bob.decryptor().update(cifrado) + cipher_bob.decryptor().finalize()

print("Mensaje descifrado:", descifrado.decode())

