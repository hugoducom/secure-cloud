#!/usr/bin/env python3
import pysodium


def argon2(password_hash: bytes) -> bytes:
    """
    Generate a master key with Argon2id. Take a random salt and the password hash as input.
    :param password_hash: Password hash
    :return: New password hash (containing generated salt)
    """
    return pysodium.crypto_pwhash_str(password_hash, pysodium.crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
                                      pysodium.crypto_pwhash_argon2i_MEMLIMIT_MODERATE)


def verify_password_hash(password_hash: bytes, hash_to_verify: bytes) -> bool:
    """
    Verify a password hash
    :param password_hash: Password hash
    :param hash_to_verify: Password hash to verify
    :return: bool
    """
    return pysodium.crypto_pwhash_str_verify(password_hash, hash_to_verify)
