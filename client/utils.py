#!/usr/bin/env python3
import os
from models import UserMetadata, User, FolderMetadata, Folder
from client.crypto import *
from client import file_manager as client_file_manager
from typing import Optional


def decrypt_user_metadata(user_metadata: UserMetadata, master_key: bytes) -> User:
    """
    Decrypt the user metadata
    :param user_metadata: UserMetadata object
    :param master_key: Master key
    :return: User object
    """
    # Compute the stretched master key
    stretched_master_key = hkdf_stretched_master_key(master_key)

    # Decrypt the symmetric key
    sym_key = xcha_cha_20_poly_1305_decrypt(user_metadata.encrypted_sym_key[0],
                                            user_metadata.encrypted_sym_key[1],
                                            user_metadata.encrypted_sym_key[2],
                                            stretched_master_key)
    # Decrypt the private key
    private_key = xcha_cha_20_poly_1305_decrypt(user_metadata.encrypted_private_key[0],
                                                user_metadata.encrypted_private_key[1],
                                                user_metadata.encrypted_private_key[2],
                                                sym_key)
    # Create the User object
    return User(user_metadata.username, stretched_master_key, sym_key, private_key, user_metadata.public_key)


def decrypt_folder_metadata(folder_metadata: FolderMetadata, user: User) -> Optional[Folder]:
    """
    Decrypt the folder metadata
    :param folder_metadata: FolderMetadata object
    :param user: User object
    :return: FolderMetadata object
    """
    # Decrypt the symmetric key
    sym_key = xcha_cha_20_poly_1305_decrypt(folder_metadata.enc_sym_key[0],
                                            folder_metadata.enc_sym_key[1],
                                            folder_metadata.enc_sym_key[2],
                                            user.sym_key)
    base_path = client_file_manager.get_root_path_for_user(user.username)
    # If user root folder
    if folder_metadata.uuid == folder_metadata.owner:
        return Folder(folder_metadata.owner, base_path, sym_key, folder_metadata)

    # Decrypt the name
    name = xcha_cha_20_poly_1305_decrypt(folder_metadata.enc_name[0],
                                         folder_metadata.enc_name[1],
                                         folder_metadata.enc_name[2],
                                         sym_key)

    # Create the Folder object
    rel_path = folder_metadata.vault_path.split(folder_metadata.owner)[1]
    path = os.path.join(os.path.join(base_path, rel_path), name.decode('utf-8'))
    return Folder(name.decode('utf-8'), path, sym_key, folder_metadata)
