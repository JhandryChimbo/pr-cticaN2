from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes

clave_privada_ecdsa = ec.generate_private_key(ec.SECP256R1())
clave_publica_ecdsa = clave_privada_ecdsa.public_key()

clave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
clave_publica = clave_privada.public_key()

mensaje = b"Mensaje firmado con ECDSA"

firma_ecdsa = clave_privada_ecdsa.sign(mensaje, ec.ECDSA(hashes.SHA256()))

try:
    clave_publica_ecdsa.verify(firma_ecdsa, mensaje, ec.ECDSA(hashes.SHA256()))
    print("Firma ECDSA verificada correctamente")
except Exception:
    print("Falló la verificación ECDSA")

firma_rsa = clave_privada.sign(
    mensaje,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

print("Tamaño firma RSA:", len(firma_rsa), "bytes")
print("Tamaño firma ECDSA:", len(firma_ecdsa), "bytes")

