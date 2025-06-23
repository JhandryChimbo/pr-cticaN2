from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

clave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
clave_publica = clave_privada.public_key()

mensaje = b"Probando firma con distintos hashes"

firma_sha256 = clave_privada.sign(
    mensaje,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

firma_sha512 = clave_privada.sign(
    mensaje,
    padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA512()
)

print("Tamaño firma SHA-256:", len(firma_sha256), "bytes")
print("Tamaño firma SHA-512:", len(firma_sha512), "bytes")

try:
    clave_publica.verify(
        firma_sha256,
        mensaje,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Verificación SHA-256 exitosa")
except Exception as e:
    print("Verificación SHA-256 fallida:", e)

try:
    clave_publica.verify(
        firma_sha256,
        mensaje,
        padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA512()
    )
    print("Verificación SHA-512 exitosa")
except Exception as e:
    print("Verificación SHA-512 fallida", e)

