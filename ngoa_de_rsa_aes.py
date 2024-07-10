import random
import numpy as np
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import os
import time
from Crypto.Util.Padding import pad, unpad
import logging
from sympy import isprime

# Setup logging
logging.basicConfig(level=logging.DEBUG)

def lorenz_step(x, y, z, sigma, rho, beta, dt=0.01):
    dx = sigma * (y - x) * dt
    dy = (x * (rho - z) - y) * dt
    dz = (x * y - beta * z) * dt
    return x + dx, y + dy, z + dz

def chen_step(x, y, z, alpha, beta, delta, dt=0.01):
    dx = alpha * (y - x) * dt
    dy = (beta * x - y - x * z) * dt
    dz = (delta * z + x * y - z) * dt
    return x + dx, y + dy, z + dz

def multi_chaotic_key_expansion(key, rounds, lorenz_params, chen_params):
    sigma, rho, beta = lorenz_params
    alpha, chen_beta, delta = chen_params
    x, y, z = key[:3]
    key_stream = []

    for _ in range(rounds):
        x, y, z = lorenz_step(x, y, z, sigma, rho, beta)
        x, y, z = chen_step(x, y, z, alpha, chen_beta, delta)

        if abs(x) > 1e6: x = 1e6 * (x / abs(x))
        if abs(y) > 1e6: y = 1e6 * (y / abs(y))
        if abs(z) > 1e6: z = 1e6 * (z / abs(z))

        key_stream.append(x)
        key_stream.append(y)
        key_stream.append(z)

    key_stream = [min(max(int(abs(k) * 10 ** 6) % 256, 0), 255) for k in key_stream]
    logging.debug(f"Key stream generated: {key_stream}")

    return bytes(key_stream[:32])

def multi_chaotic_aes_encrypt(data, key, rounds, lorenz_params, chen_params):
    key_stream = multi_chaotic_key_expansion(key, rounds, lorenz_params, chen_params)
    cipher = AES.new(key_stream[:16], AES.MODE_EAX)
    nonce = cipher.nonce
    start_time = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end_time = time.time()
    encryption_time = end_time - start_time
    logging.debug(f"Encryption time: {encryption_time} seconds")
    return nonce + ciphertext, encryption_time

def multi_chaotic_aes_decrypt(ciphertext, key, rounds, lorenz_params, chen_params):
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    key_stream = multi_chaotic_key_expansion(key, rounds, lorenz_params, chen_params)
    cipher = AES.new(key_stream[:16], AES.MODE_EAX, nonce=nonce)
    start_time = time.time()
    data = cipher.decrypt(ciphertext)
    end_time = time.time()
    decryption_time = end_time - start_time
    logging.debug(f"Decryption time: {decryption_time} seconds")
    return data, decryption_time

def generate_key(bit_size):
    key = get_random_bytes(bit_size // 8)
    logging.debug(f"Generated key: {key}")
    return key

def applyNthRootFunction(matrix, N):
    return np.power(matrix, 1 / N)

def mixColumn(matrix, N, inverse=False):
    MIX_COLUMN_MATRIX = np.array([
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ], dtype=np.uint8)

    INVERSE_MIX_COLUMN_MATRIX = np.array([
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ], dtype=np.uint8)

    matrix = applyNthRootFunction(matrix, N)
    mix_column_matrix = INVERSE_MIX_COLUMN_MATRIX if inverse else MIX_COLUMN_MATRIX

    result = np.zeros_like(matrix, dtype=np.float64)
    for col in range(4):
        for row in range(4):
            result[row, col] = np.sum(mix_column_matrix[row, :] * matrix[:, col]) % 256

    logging.debug(f"MixColumn result: {result}")
    return result

def encrypt_data(data, N):
    data_array = np.frombuffer(data, dtype=np.uint8)
    if data_array.size % 16 != 0:
        padding_length = 16 - (data_array.size % 16)
        data_array = np.pad(data_array, (0, padding_length), mode='constant')
    matrix = data_array.reshape(-1, 4, 4)
    encrypted_matrices = [mixColumn(matrix_part, N) for matrix_part in matrix]
    encrypted_data = np.concatenate([matrix.flatten() for matrix in encrypted_matrices]).astype(np.uint8)
    logging.debug(f"Encrypted data with MixColumn: {encrypted_data}")
    return encrypted_data

def decrypt_data(data, N):
    data_array = np.frombuffer(data, dtype=np.uint8)
    matrix = data_array.reshape(-1, 4, 4)
    decrypted_matrices = [mixColumn(matrix_part, N, inverse=True) for matrix_part in matrix]
    decrypted_data = np.concatenate([matrix.flatten() for matrix in decrypted_matrices]).astype(np.uint8)
    logging.debug(f"Decrypted data with MixColumn: {decrypted_data}")
    return decrypted_data

def rsa_key_generation(key_bits):
    e = 65537
    while True:
        p = random.getrandbits(key_bits // 2)
        q = random.getrandbits(key_bits // 2)
        
        # Ensure p and q are prime
        if not isprime(p) or not isprime(q):
            continue
        
        # Ensure p and q are not equal
        if p == q:
            continue
        
        # Calculate modulus n
        n_rsa = p * q
        
        # Ensure the modulus n is odd
        if n_rsa % 2 == 0:
            continue
        
        # Calculate the totient
        phi = (p - 1) * (q - 1)
        
        # Ensure e and phi are coprime
        if (p - 1) % e == 0 or (q - 1) % e == 0:
            continue

        # Calculate the private exponent d
        d_rsa = inverse(e, phi)
        
        return (n_rsa, e), (n_rsa, d_rsa)

def ngoa_de_rsa_aes_encrypt(filename, key_bits):
    key = generate_key(128)
    rounds = 10
    lorenz_params = (10.0, 28.0, 8.0 / 3.0)
    chen_params = (35.0, 3.0, 12.0)

    with open(filename, 'rb') as f:
        data = f.read()

    padded_data = pad(data, AES.block_size)
    encrypted_data, encryption_time = multi_chaotic_aes_encrypt(padded_data, key, rounds, lorenz_params, chen_params)
    encrypted_data_with_mixcolumn = encrypt_data(encrypted_data, 3)

    (n_rsa, e), (n_rsa, d_rsa) = rsa_key_generation(key_bits)
    public_key = RSA.construct((n_rsa, e))
    private_key = RSA.construct((n_rsa, d_rsa))
    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_key = cipher_rsa.encrypt(key)

    encrypted_filename = filename + '.enc'
    with open(encrypted_filename, 'wb') as f:
        f.write(encrypted_key + encrypted_data_with_mixcolumn)

    logging.info(f"File encrypted and saved as: {encrypted_filename}")
    return encrypted_filename

def ngoa_de_rsa_aes_decrypt(encrypted_filename, private_key_path):
    with open(encrypted_filename, 'rb') as f:
        encrypted_data = f.read()

    key_bits = len(encrypted_data) * 8
    private_key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    encrypted_key = encrypted_data[:private_key.size_in_bytes()]
    encrypted_data_with_mixcolumn = encrypted_data[private_key.size_in_bytes():]

    key = cipher_rsa.decrypt(encrypted_key)
    decrypted_data_with_mixcolumn = decrypt_data(encrypted_data_with_mixcolumn, 3)
    decrypted_data, _ = multi_chaotic_aes_decrypt(decrypted_data_with_mixcolumn, key, 10, (10.0, 28.0, 8 / 3), (35.0, 3.0, 12.0))
    unpadded_data = unpad(decrypted_data, AES.block_size)

    decrypted_filename = encrypted_filename + '.dec'
    with open(decrypted_filename, 'wb') as f:
        f.write(unpadded_data)

    logging.info(f"File decrypted and saved as: {decrypted_filename}")
    return decrypted_filename