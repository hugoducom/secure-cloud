#!/usr/bin/env python3
import pysodium
from Crypto.Hash import SHA512, SHAKE128
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from client.consts import KEY_LENGTH_BYTES, HKDF_CONTEXT_1, HKDF_CONTEXT_2, HKDF_SALT

def argon2(password_hash):
    """
    Generate a master key with Argon2id. Take the username as salt and password as input.
    :param password_hash: Password hash as bytes string
    :return: Master key as bytes string
    """
    # Hash the username to fit the salt size
    salt = SHAKE128.new(username.encode()).read(pysodium.crypto_pwhash_SALTBYTES)
    # Hashed in 1.02 second with a Lenovo Thinkpad E14
    return pysodium.crypto_pwhash(outlen=KEY_LENGTH_BYTES, passwd=password, salt=salt,
                                  opslimit=pysodium.crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
                                  memlimit=pysodium.crypto_pwhash_argon2i_MEMLIMIT_MODERATE,
                                  alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)