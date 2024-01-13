#!/usr/bin/env python3
import pysodium
from Crypto.Hash import SHA512, SHAKE128
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from consts import KEY_LENGTH_BYTES, HKDF_CONTEXT_1, HKDF_CONTEXT_2, HKDF_SALT


def generate_master_key(username: str, password: str) -> bytes:
    """
    Generate a master key with Argon2id. Take the username as salt and password as input
    :param username: Username
    :param password: Password
    :return: Master key
    """
    # Hash the username to fit the salt size
    salt = SHAKE128.new(username.encode('utf-8')).read(pysodium.crypto_pwhash_SALTBYTES)
    # Hashed in 1.02 second with a Lenovo Thinkpad E14
    return pysodium.crypto_pwhash(outlen=KEY_LENGTH_BYTES, passwd=password, salt=salt,
                                  opslimit=pysodium.crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
                                  memlimit=pysodium.crypto_pwhash_argon2i_MEMLIMIT_MODERATE,
                                  alg=pysodium.crypto_pwhash_ALG_ARGON2ID13)


def hkdf_stretched_master_key(secret: bytes) -> bytes:
    """
    Derive a stretched master key from a secret
    :param secret: Bytes string
    :return: Stretched master key
    """
    return HKDF(master=secret, key_len=KEY_LENGTH_BYTES, hashmod=SHA512, salt=HKDF_SALT, context=HKDF_CONTEXT_1)


def hkdf_password_hash(secret: bytes) -> bytes:
    """
    Derive a password hash from a secret
    :param secret: Bytes string
    :return: Password hash as bytes string
    """
    return HKDF(master=secret, key_len=KEY_LENGTH_BYTES, hashmod=SHA512, salt=HKDF_SALT, context=HKDF_CONTEXT_2)


def xcha_cha_20_poly_1305_encrypt(message: bytes, nonce: bytes, key: bytes) -> (bytes, bytes, bytes):
    """
    Encrypt a message with XChaCha20-Poly1305
    :param message: Message to encrypt
    :param nonce: Nonce (should be 24 bytes long)
    :param key: Key
    :return: Tuple of (nonce, ciphertext, tag)
    """
    if len(nonce) != 24:
        raise ValueError("Nonce must be 24 bytes long")
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag


def xcha_cha_20_poly_1305_decrypt(message: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
    """
    Decrypt a message with XChaCha20-Poly1305
    :param message: Message
    :param nonce: Nonce (should be 24 bytes long)
    :param tag: Tag
    :param key: Key
    :return: Original message
    """
    if len(nonce) != 24:
        raise ValueError("Nonce must be 24 bytes long")
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(message, tag)


def generate_asym_keys(size: int = 3072) -> RSA.RsaKey:
    """
    Generate RSA key pair
    :param size: Size of the key in bits
    :return: New RSA Key object
    """
    # keylength.com from ECRYPT recommandations
    return RSA.generate(size)


def encrypt_asym(key_to_encrypt: bytes, public_key: RSA.RsaKey) -> bytes:
    """
    Encrypt a key with RSA OAEP PKCS#1 v2.2
    :param key_to_encrypt: key to encrypt
    :param public_key: RSA key to encrypt with
    :return: Encrypted message
    """
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA512.new())
    return cipher.encrypt(key_to_encrypt)


def decrypt_asym(key_to_decrypt: bytes, private_key: RSA.RsaKey) -> bytes:
    """
    Decrypt a key with RSA OAEP PKCS#1 v2.2
    :param key_to_decrypt: key to decrypt
    :param private_key: RSA key to decrypt with
    :return: Original message
    """
    cipher = PKCS1_OAEP.new(key=private_key, hashAlgo=SHA512.new())
    return cipher.decrypt(key_to_decrypt)
