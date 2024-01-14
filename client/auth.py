#!/usr/bin/env python3
import Crypto.Random
from server import api as server_api
from client.session import Session, set_session_user, get_session_user
from client.utils import *
import client.file_manager as client_file_manager


def register(username: str, password: str) -> bool:
    """
    Register a new user
    :param username: Username
    :param password: Password
    :return: bool
    """
    print("Registering...")
    # Generate password_hash
    master_key, password_hash = generate_password_hash(username, password)
    stretched_master_key = hkdf_stretched_master_key(master_key)

    # Generate symmetric key (256 bits)
    sym_key = Crypto.Random.get_random_bytes(KEY_LENGTH_BYTES)
    nonce1 = Crypto.Random.get_random_bytes(24)
    # Cipher to send it to the server
    _, encrypted_sym_key, tag1 = xcha_cha_20_poly_1305_encrypt(sym_key, nonce1, stretched_master_key)

    # Generate asymmetric key
    rsa_key = generate_asym_keys()
    private_key = rsa_key.exportKey()
    nonce2 = Crypto.Random.get_random_bytes(24)
    # Cipher to send it to the server
    _, encrypted_private_key, tag2 = xcha_cha_20_poly_1305_encrypt(private_key, nonce2, sym_key)

    # Create the UserMetadata object
    user_metadata = UserMetadata(username, password_hash, (encrypted_sym_key, nonce1, tag1),
                                 (encrypted_private_key, nonce2, tag2), rsa_key.publickey().exportKey())

    # Init the local root folder
    user = User(username, stretched_master_key, sym_key, private_key, rsa_key.publickey().exportKey())
    client_file_manager.init(user)
    # Create the user root folder metadata
    root_sym_key = Crypto.Random.get_random_bytes(KEY_LENGTH_BYTES)
    nonce = Crypto.Random.get_random_bytes(24)
    _, encrypted_root_sym_key, tag = xcha_cha_20_poly_1305_encrypt(root_sym_key, nonce, sym_key)
    root_metadata: FolderMetadata = FolderMetadata(
        uuid=username,
        enc_name=(b"\x00", b"\x00", b"\x00"),
        enc_sym_key=(encrypted_root_sym_key, nonce, tag),
        vault_path="",  # Has to be set by the server
        owner=username,
        nodes=[],
    )

    return server_api.register_request(user_metadata.to_json(), root_metadata.to_json())


def login(username: str, password: str) -> bool:
    """
    Login a user
    :param username: Username
    :param password: Password
    :return: bool
    """
    master_key, password_hash = generate_password_hash(username, password)
    password_hash = hkdf_password_hash(master_key)

    ret = server_api.login_request(username, password_hash)
    # Login failed
    if not ret:
        return False

    user: User = decrypt_user_metadata(ret, master_key)
    root_folder_metadata: FolderMetadata = server_api.get_user_root_folder_request(user.username)
    root_folder: Folder = decrypt_folder_metadata(root_folder_metadata, user)
    set_session_user(Session(user, root_folder))
    return True


def generate_password_hash(username: str, password: str) -> (bytes, bytes):
    """
    Generate a password hash
    :param username: Username
    :param password: Password
    :return: (master_key, password_hash)
    """
    master_key = generate_master_key(username, password)
    return master_key, hkdf_password_hash(master_key)


def change_password(username: str, old_password: str, new_password: str) -> bool:
    """
    Change the password of the connected user
    :param username: Username as string
    :param old_password: Old password
    :param new_password: New password
    :return: bool
    """
    session = get_session_user()
    if session is None:
        print("You are not connected")
        return False
    # Generate the new password hash
    new_master_key, new_password_hash = generate_password_hash(username, new_password)
    new_stretched_master_key = hkdf_stretched_master_key(new_master_key)
    # Generate the old password hash
    old_master_key, old_password_hash = generate_password_hash(username, old_password)

    # Generate the new encrypted symmetric key
    nonce = Crypto.Random.get_random_bytes(24)
    _, new_enc_sym_key, tag = xcha_cha_20_poly_1305_encrypt(session.user.sym_key, nonce, new_stretched_master_key)

    # Change the password on the server
    return server_api.change_password_request(username, old_password_hash, new_password_hash,
                                              (new_enc_sym_key, nonce, tag))
