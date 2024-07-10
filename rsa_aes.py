from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def rsa_aes_encrypt(filename, key_bits):
    if key_bits < 1024:
        raise ValueError("RSA key length must be at least 1024 bits")
    
    key = RSA.generate(key_bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    aes_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv

    with open(filename, 'rb') as f:
        plaintext = f.read()

    ciphertext_aes = iv + cipher_aes.encrypt(pad(plaintext, AES.block_size))

    encrypted_filename = f"{filename}.enc"
    with open(encrypted_filename, 'wb') as f:
        f.write(encrypted_aes_key + ciphertext_aes)

    with open('rsa_private_key.pem', 'wb') as f:
        f.write(private_key)

    return encrypted_filename

def rsa_aes_decrypt(encrypted_filename, private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)

    with open(encrypted_filename, 'rb') as f:
        encrypted_aes_key = f.read(private_key.size_in_bytes())
        ciphertext_aes = f.read()

    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    iv = ciphertext_aes[:16]
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher_aes.decrypt(ciphertext_aes[16:]), AES.block_size)

    decrypted_filename = f"{encrypted_filename}.dec"
    with open(decrypted_filename, 'wb') as f:
        f.write(plaintext)

    return decrypted_filename
