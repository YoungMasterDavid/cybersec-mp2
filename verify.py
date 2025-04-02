from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_signature(encrypted_message: str, signature: str):
    public_key = load_public_key("signing_public.pem")
    try:
        public_key.verify(
            base64.b64decode(signature),
            encrypted_message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    encrypted_message = input("Enter encrypted message: ")
    signature = input("Enter signature: ")
    if verify_signature(encrypted_message, signature):
        print("Signature is valid.")
    else:
        print("Signature verification failed!")