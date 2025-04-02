from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

def load_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def decrypt_message(encrypted_message: str):
    private_key = load_key("encryption_private.pem")
    decrypted_message = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

if __name__ == "__main__":
    encrypted_message = input("Enter encrypted message: ")
    decrypted_message = decrypt_message(encrypted_message)
    print(f"Decrypted Message: {decrypted_message}")