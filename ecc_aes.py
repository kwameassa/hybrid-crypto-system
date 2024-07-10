from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def ecc_aes_encrypt(filename):
    # Generate ECC key pair
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    # Perform key agreement to derive a shared secret
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive AES key from the shared secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv

    with open(filename, 'rb') as f:
        plaintext = f.read()

    ciphertext_aes = cipher_aes.encrypt(pad(plaintext, AES.block_size))

    encrypted_filename = f"{filename}.enc"
    with open(encrypted_filename, 'wb') as f:
        f.write(iv + ciphertext_aes)

    # Save the private key for decryption
    with open('ecc_private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return encrypted_filename

def ecc_aes_decrypt(encrypted_filename, private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Perform key agreement to derive the shared secret
    public_key = private_key.public_key()
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive AES key from the shared secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    with open(encrypted_filename, 'rb') as f:
        iv = f.read(16)
        ciphertext_aes = f.read()

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext_aes), AES.block_size)

    decrypted_filename = f"{encrypted_filename}.dec"
    with open(decrypted_filename, 'wb') as f:
        f.write(plaintext)

    return decrypted_filename
