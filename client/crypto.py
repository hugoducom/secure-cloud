#!/usr/bin/env python3
import pysodium
from Crypto.Hash import SHA512, SHAKE128
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from client.consts import KEY_LENGTH_BYTES, HKDF_CONTEXT_1, HKDF_CONTEXT_2, HKDF_SALT


def generate_master_key(username, password):
    """
    Generate a master key with Argon2id. Take the username as salt and password as input.
    :param username: Username as string
    :param password: Password as string
    :return: Master key as bytes string
    """
    # Hash the username to fit the salt size
    salt = SHAKE128.new(username.encode()).read(pysodium.crypto_pwhash_SALTBYTES)
    # Hashed in 1.02 second with a Lenovo Thinkpad E14
    return pysodium.crypto_pwhash(outlen=KEY_LENGTH_BYTES, passwd=password, salt=salt,
                                  opslimit=pysodium.crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
                                  memlimit=pysodium.crypto_pwhash_argon2i_MEMLIMIT_MODERATE,
                                  alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)


def hkdf_stretched_master_key(secret):
    """
    Derive a stretched master key from a secret
    :param secret: Bytes string
    :return: Stretched master key as bytes string
    """
    return HKDF(master=secret, key_len=KEY_LENGTH_BYTES, hashmod=SHA512, salt=HKDF_SALT, context=HKDF_CONTEXT_1)


def hkdf_password_hash(secret):
    """
    Derive a password hash from a secret
    :param secret: Bytes string
    :return: Password hash as bytes string
    """
    return HKDF(master=secret, key_len=KEY_LENGTH_BYTES, hashmod=SHA512, salt=HKDF_SALT, context=HKDF_CONTEXT_2)


def xcha_cha_20_poly_1305_encrypt(message, nonce, key):
    """
    Encrypt a message with XChaCha20-Poly1305
    :param message: Message as bytes string
    :param nonce: Nonce as bytes string (should be 24 bytes long)
    :param key: Key as bytes string
    :return: Tuple of nonce, ciphertext and tag each as bytes string
    """
    if len(nonce) != 24:
        raise ValueError("Nonce must be 24 bytes long")
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag


def xcha_cha_20_poly_1305_decrypt(message, nonce, tag, key):
    """
    Decrypt a message with XChaCha20-Poly1305
    :param message: Message as bytes string
    :param nonce: Nonce as bytes string (should be 24 bytes long)
    :param tag: Tag as bytes string
    :param key: Key as bytes string
    :return: Original message as bytes string
    """
    if len(nonce) != 24:
        raise ValueError("Nonce must be 24 bytes long")
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(message, tag)


def generate_asym_keys(size=3072):
    """
    Generate RSA key pair
    :param size: Size of the key in bits
    :return: New RSA Key object
    """
    # keylength.com from ECRYPT recommandations
    return RSA.generate(size)


def encrypt_asym(key_to_encrypt, public_key):
    """
    Encrypt a key with RSA OAEP
    :param key_to_encrypt: key to encrypt as string or byte string
    :param public_key: RSA key to encrypt with as RSA Key object
    :return: Encrypted message in bytes
    """
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA512.new())
    return cipher.encrypt(key_to_encrypt)


def decrypt_asym(key_to_decrypt, private_key):
    """
    Decrypt a key with RSA OAEP
    :param key_to_decrypt: key to decrypt as string or byte string
    :param private_key: RSA key to decrypt with as RSA Key object
    :return: Original message in bytes
    """
    cipher = PKCS1_OAEP.new(key=private_key, hashAlgo=SHA512.new())
    return cipher.decrypt(key_to_decrypt)
