from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

clave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
clave_publica = clave_privada.public_key()
print("Clave pública de Alice generada.")

mensaje = b"Documento firmado por Alice"
firma = clave_privada.sign(
    mensaje,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

try:
    clave_publica.verify(
        firma,
        mensaje,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        algorithm=hashes.SHA256()
    )
    print("Charlie verifica la firma de Alice. Autenticidad y no repudio confirmados.")
except Exception:
    print("Charlie no pudo verificar la firma.")

