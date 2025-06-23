from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
clave_publica = clave_privada.public_key()

mensaje = b"Jhandry Santiago Chimbo Rivera"

firma = clave_privada.sign(
    mensaje,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

mensaje_modificado = b"Jhandry Santiago Chimbo Rivera"

try:
    clave_publica.verify(
        signature=firma,
        data=mensaje_modificado,
        padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        algorithm=hashes.SHA256()
    )
    print("La firma es válida: la integridad se mantiene")
except Exception:
    print("La firma no es válida: la integridad fue comprometida")
