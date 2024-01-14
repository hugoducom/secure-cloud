#!/usr/bin/env python3
import os

import Crypto.Random
import Crypto.PublicKey.RSA

from models import UserMetadata, User, FolderMetadata, Folder, NodeMetadata, ShareMetadata, Share
from client.crypto import *
from client import file_manager as client_file_manager
from typing import Optional
from server import api as server_api


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

    # Decrypt the eventual shares with his private key
    shares: list[Share] = []
    rsa_private_key = Crypto.PublicKey.RSA.import_key(private_key)
    if user_metadata.shares is not None:
        for share_metadata in user_metadata.shares:
            shares.append(Share(
                name=decrypt_asym(share_metadata.enc_name, rsa_private_key).decode('utf-8'),
                sym_key=decrypt_asym(share_metadata.enc_sym_key, rsa_private_key),
                folder_path="[client/utils] TOCHANGE",
                metadata=share_metadata
            ))

    # Create the User object
    return User(user_metadata.username, stretched_master_key, sym_key, private_key, user_metadata.public_key, shares)


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
    return Folder(name.decode('utf-8'), "TO CHANGE AT RETURN", decrypted_sym_key, folder_metadata)


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


def get_folder_from_server(current_folder: Folder, user: User, folder_name: str) -> Optional[Folder]:
    """
    Get a folder from the server
    :param current_folder:
    :param user:
    :param folder_name:
    :return:
    """
    node: NodeMetadata = search_node_metadata_by_name(current_folder, folder_name)
    if node is None:
        return None
    new_folder_metadata: FolderMetadata = server_api.get_folder_metadata_request(
        os.path.join(current_folder.metadata.vault_path, current_folder.metadata.uuid, node.uuid),
        node.uuid
    )
    if new_folder_metadata is None:
        return None
    new_folder: Folder = decrypt_folder_metadata(new_folder_metadata, current_folder.sym_key, user)
    if new_folder is None:
        return None
    # Change the path of the folder
    new_folder.folder_path = os.path.join(current_folder.folder_path, new_folder.folder_name)
    return new_folder


def encrypt_folder_for_sharing(folder_to_share: Folder, user_to_share: UserMetadata) -> ShareMetadata:
    """
    Encrypt a folder for sharing
    :param folder_to_share: Folder to share
    :param user_to_share: User to share with
    :return: ShareMetadata object
    """
    # Encrypt the folder symmetric key with the user public key
    rsa_key = Crypto.PublicKey.RSA.import_key(user_to_share.public_key)
    enc_sym_key = encrypt_asym(folder_to_share.sym_key, rsa_key)
    enc_name = encrypt_asym(folder_to_share.folder_name.encode('utf-8'), rsa_key)
    return ShareMetadata(
        enc_name=enc_name,
        enc_sym_key=enc_sym_key,
        vault_path=folder_to_share.metadata.vault_path,
        uuid=folder_to_share.metadata.uuid,
    )


def convert_share_to_folder(share: Share, folder_metadata: FolderMetadata) -> Folder:
    """
    Convert a share to a folder
    :param share: Share object
    :param folder_metadata: FolderMetadata object to bind with
    :return: Folder object
    """
    return Folder(
        folder_name=share.name,
        folder_path=os.path.join(share.folder_path, share.name),
        sym_key=share.sym_key,
        metadata=folder_metadata
    )


def get_share_folder_from_server(share: Share, base_path: str) -> Optional[Folder]:
    """
    Get a share folder from the server
    :param share: Share object
    :param base_path: Base path of local structure
    :return: Folder object
    """
    folder_metadata: FolderMetadata = server_api.get_folder_metadata_request(
        os.path.join(share.metadata.vault_path, share.metadata.uuid), share.metadata.uuid)
    if folder_metadata is None:
        return None
    # Decrypt the folder metadata
    downloaded_folder: Folder = convert_share_to_folder(share, folder_metadata)

    if downloaded_folder is None:
        return None
    # Set the local folder_path
    downloaded_folder.folder_path = os.path.join(base_path, "shares", downloaded_folder.folder_name)
    return downloaded_folder
