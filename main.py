#!/usr/bin/env python3
import Crypto.Random
import pysodium
from client import *


def main():
    print("Hello World")

    salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    master_key = crypto.generate_master_key("password", salt)
    print(f"Master key : {master_key}")

    stretched_master_key = crypto.hkdf_stretched_master_key(master_key)
    print(f"Stretched master key : {stretched_master_key}")

    password_hash = crypto.hkdf_password_hash(master_key)
    print(f"Password hash : {password_hash}")

    sym_key = Crypto.Random.get_random_bytes(32)
    print(f"Sym key : {sym_key}")
    nonce = Crypto.Random.get_random_bytes(24)
    _, encrypted_sym_key, tag = crypto.xcha_cha_20_poly_1305_encrypt(sym_key, nonce, stretched_master_key)
    print(f"Encrypted sym key : {nonce}, {encrypted_sym_key}, {tag}")

    decrypted_sym_key = crypto.xcha_cha_20_poly_1305_decrypt(encrypted_sym_key, nonce, tag, stretched_master_key)
    print(f"Decrypted sym key : {decrypted_sym_key}")

    rsa_key = crypto.generate_asym_keys()
    print(f"RSA key : {rsa_key.exportKey()}")

    encrypted_asym_key = crypto.encrypt_asym(rsa_key.exportKey(), rsa_key)
    print(f"Encrypted asym key : {encrypted_asym_key}")

    decrypted_asym_key = crypto.decrypt_asym(encrypted_asym_key, rsa_key)
    print(f"Decrypted asym key : {decrypted_asym_key}")


if __name__ == '__main__':
    main()
