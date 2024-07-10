from flask import Flask, render_template, request, jsonify
import os
from rsa_aes import rsa_aes_encrypt, rsa_aes_decrypt
from ecc_aes import ecc_aes_encrypt, ecc_aes_decrypt
from ngoa_de_rsa_aes import ngoa_de_rsa_aes_encrypt, ngoa_de_rsa_aes_decrypt
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    encryption_method = request.form['encryption_method']
    key_bits = int(request.form['key_bits'])

    filename = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
    file.save(filename)

    try:
        if encryption_method == 'RSA/AES':
            encrypted_filename = rsa_aes_encrypt(filename, key_bits)
        elif encryption_method == 'ECC/AES':
            encrypted_filename = ecc_aes_encrypt(filename)
        elif encryption_method == 'NGOA-DE-RSA/M-AES':
            encrypted_filename = ngoa_de_rsa_aes_encrypt(filename, key_bits)
        else:
            return jsonify({'error': 'Invalid encryption method'})
    except ValueError as e:
        logging.error(f"Error during encryption: {e}")
        return jsonify({'error': str(e)})

    logging.info(f"Encryption completed, encrypted file saved as: {encrypted_filename}")
    return jsonify({'success': 'Encryption completed', 'encrypted_file': encrypted_filename})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    decryption_method = request.form['encryption_method']
    encrypted_filename = request.form['encrypted_file']
    private_key_path = request.form['private_key_path']

    try:
        if decryption_method == 'RSA/AES':
            decrypted_filename = rsa_aes_decrypt(encrypted_filename, private_key_path)
        elif decryption_method == 'ECC/AES':
            decrypted_filename = ecc_aes_decrypt(encrypted_filename, private_key_path)
        elif decryption_method == 'NGOA-DE-RSA/M-AES':
            decrypted_filename = ngoa_de_rsa_aes_decrypt(encrypted_filename, private_key_path)
        else:
            return jsonify({'error': 'Invalid decryption method'})
    except ValueError as e:
        logging.error(f"Error during decryption: {e}")
        return jsonify({'error': str(e)})

    logging.info(f"Decryption completed, decrypted file saved as: {decrypted_filename}")
    return jsonify({'success': 'Decryption completed', 'decrypted_file': decrypted_filename})

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
