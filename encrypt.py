from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_message(message: str):
    public_key = load_public_key("encryption_public.pem")
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

if __name__ == "__main__":
    message = "Hello, this is a secure message!"
    encrypted_message = encrypt_message(message)
    print(f"Encrypted Message: {encrypted_message}")