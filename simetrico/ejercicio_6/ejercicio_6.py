from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def cifrado_chacha20(mensaje):
    clave = get_random_bytes(32)
    nonce = get_random_bytes(12)

    # Cifrado
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    ciphertext = cipher.encrypt(mensaje.encode())

    # Descifrado
    decipher = ChaCha20.new(key=clave, nonce=nonce)
    mensaje_descifrado = decipher.decrypt(ciphertext)

    return ciphertext, mensaje_descifrado.decode()

cifrado, descifrado = cifrado_chacha20("Entrenamiento de un modelo predictivo mediante Random Forest (basado en árboles de decisión) para la detección de enfermedades cardiovasculares asociadas a hipertensión arterial.")
print("Cifrado:", cifrado)
print("Descifrado:", descifrado)

