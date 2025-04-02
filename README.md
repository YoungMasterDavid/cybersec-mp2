# cybersec-mp2

keygen.py – Generates RSA key pairs (encryption & signing).
encrypt.py – Encrypts a message using RSA-OAEP.
sign.py – Signs the encrypted message.
verify.py – Verifies the signature.
decrypt.py – Decrypts the message after verification.

**How to run:**
1. On terminal enter:
python keygen.py

This will generate the following files:
 - encryption_private.pem (for decrypting)
 - encryption_public.pem (for encrypting)
 - signing_private.pem (for signing)
 - signing_public.pem (for verifying)

2. Run the encryption script to send the messagen "Hello, this is a secure message!":
python encrypt.py

Example output: Encrypted Message: b64_encoded_ciphertext_here

3. Copy the encrypted message and use it to generate a signature:
python sign.py
Example output: b64_encoded_signature_here

4. Run the verification script:
python verify.py

Enter the encrypted message and signature. If they match, you’ll see:
Signature is valid.

If they don’t match:
Signature verification failed!

5. If the signature is valid, you can now decrypt the message:
python decrypt.py

**Workflow**

Enter the encrypted message, and it will output the original plaintext message.

Run keygen.py → Generates keys

Run encrypt.py → Outputs ciphertext

Run sign.py → Outputs signature

Run verify.py → Checks signature validity

Run decrypt.py → Outputs original message

Now you have a fully working encrypt-then-sign RSA-OAEP system! 🚀 Let me know if you need further clarification.