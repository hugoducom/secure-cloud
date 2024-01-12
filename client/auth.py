#!/usr/bin/env python3
from client.crypto import *
import Crypto.Random
from client.consts import KEY_LENGTH_BYTES

def register(username, password):
    # Generate password_hash
    master_key, password_hash = generate_password_hash(username, password)
    stretched_master_key = hkdf_stretched_master_key(master_key)

    # Generate symmetric key (256 bits)
    sym_key = Crypto.Random.get_random_bytes(KEY_LENGTH_BYTES)
    nonce1 = Crypto.Random.get_random_bytes(24)
    # Cipher to send it to the server
    encrypted_sym_key, tag1 = xcha_cha_20_poly_1305_encrypt(sym_key, nonce1, stretched_master_key)

    # Generate asymmetric key
    rsa_key = generate_asym_keys()
    private_key = rsa_key.exportKey()
    nonce2 = Crypto.Random.get_random_bytes(24)
    # Cipher to send it to the server
    encrypted_private_key, tag2 = xcha_cha_20_poly_1305_encrypt(private_key, nonce2, sym_key)

    # TODO SEND TO SERVER PASSWORD_HASH, ENCRYPTED_SYM_KEY, NONCE1, TAG1, ENCRYPTED_PRIVATE_KEY, NONCE2, TAG2
    return password_hash, (encrypted_sym_key, nonce1, tag1), (encrypted_private_key, nonce2, tag2)

def login(username, password):
    

def generate_password_hash(username, password):
    master_key = generate_master_key(username, password)
    return master_key, hkdf_password_hash(master_key)

