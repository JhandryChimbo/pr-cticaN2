from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

# Simular clave compartida
clave_simetrica = urandom(32)
iv = urandom(16)

# Alice cifra
def alice_envia(mensaje):
    cipher = Cipher(algorithms.AES(clave_simetrica), modes.CFB(iv))
    return cipher.encryptor().update(mensaje.encode()) + cipher.encryptor().finalize()

# Bob descifra
def bob_recibe(cifrado):
    cipher = Cipher(algorithms.AES(clave_simetrica), modes.CFB(iv))
    return (cipher.decryptor().update(cifrado) + cipher.decryptor().finalize()).decode()

# Comunicación
mensaje = "Hola Bob, soy Alice"
mensaje_cifrado = alice_envia(mensaje)
mensaje_descifrado = bob_recibe(mensaje_cifrado)

print("Cifrado por Alice:", mensaje_cifrado)
print("Descifrado por Bob:", mensaje_descifrado)

