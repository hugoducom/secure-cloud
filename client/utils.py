#!/usr/bin/env python3
import os
from models import UserMetadata, User, FolderMetadata, Folder, NodeMetadata
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


def decrypt_folder_metadata(folder_metadata: FolderMetadata, sym_key: bytes, user: User) -> Optional[Folder]:
    """
    Decrypt the folder metadata
    :param folder_metadata: FolderMetadata object
    :param sym_key: Symmetric key to decrypt with
    :param user: User object
    :return: FolderMetadata object
    """
    # Decrypt the symmetric key
    decrypted_sym_key = xcha_cha_20_poly_1305_decrypt(folder_metadata.enc_sym_key[0],
                                                      folder_metadata.enc_sym_key[1],
                                                      folder_metadata.enc_sym_key[2],
                                                      sym_key)
    base_path = client_file_manager.get_root_path_for_user(user.username)
    # If user root folder
    if folder_metadata.uuid == folder_metadata.owner:
        return Folder(folder_metadata.owner, base_path, decrypted_sym_key, folder_metadata)

    # Decrypt the name
    name = xcha_cha_20_poly_1305_decrypt(folder_metadata.enc_name[0],
                                         folder_metadata.enc_name[1],
                                         folder_metadata.enc_name[2],
                                         sym_key)

    # Create the Folder object
    rel_path = folder_metadata.vault_path.split(folder_metadata.owner)[1]
    path = os.path.join(os.path.join(base_path, rel_path), name.decode('utf-8'))
    return Folder(name.decode('utf-8'), path, decrypted_sym_key, folder_metadata)


def search_node_metadata_by_name(current_folder: Folder, name: str) -> Optional[NodeMetadata]:
    """
    Get a node metadata by its name
    :param current_folder: Current folder
    :param name: Name of the node
    :return: NodeMetadata object or None
    """
    for node in current_folder.metadata.nodes:
        decrypted_node_name = xcha_cha_20_poly_1305_decrypt(node.enc_name[0], node.enc_name[1], node.enc_name[2],
                                                            current_folder.sym_key).decode('utf-8')
        if decrypted_node_name == name:
            return node
    return None
