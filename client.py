import argparse
import base64
import json
import os

import requests
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def main():
    parser = argparse.ArgumentParser(description='Faz login criptografado no servidor Flask.')
    parser.add_argument('email')
    parser.add_argument('password')
    parser.add_argument('--url', default='http://localhost:5000/api/login')
    args = parser.parse_args()

    # Chave AES (32 bytes), chave HMAC (32 bytes) e IV (16 bytes).
    aes_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv = os.urandom(16)
    session_keys = aes_key + mac_key + iv

    plaintext = json.dumps(
        {'email': args.email, 'password': args.password},
        ensure_ascii=False
    ).encode('utf-8')
    encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    signer = hmac.HMAC(mac_key, hashes.SHA256())
    signer.update(ciphertext)
    tag = signer.finalize()

    form_data = {
        'session_keys': base64.b64encode(session_keys).decode('ascii'),
        'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
        'hmac': base64.b64encode(tag).decode('ascii'),
    }

    with requests.Session() as session:
        try:
            response = session.post(args.url, data=form_data, timeout=10)
        except requests.RequestException as error:
            parser.error(f'Não foi possível conectar ao servidor: {error}')

        print(response.status_code)
        if response.ok:
            print(session.cookies.get('session_id'))
        elif response.text:
            print(response.text)


if __name__ == '__main__':
    main()
