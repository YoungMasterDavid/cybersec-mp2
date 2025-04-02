from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

def load_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_message(encrypted_message: str):
    private_key = load_key("signing_private.pem")
    signature = private_key.sign(
        encrypted_message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

if __name__ == "__main__":
    encrypted_message = input("Enter encrypted message: ")
    signature = sign_message(encrypted_message)
    print(f"Signature: {signature}")