from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys():
    encryption_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open("encryption_private.pem", "wb") as f:
        f.write(encryption_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("encryption_public.pem", "wb") as f:
        f.write(encryption_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    with open("signing_private.pem", "wb") as f:
        f.write(signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("signing_public.pem", "wb") as f:
        f.write(signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

if __name__ == "__main__":
    generate_keys()