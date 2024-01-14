#!/usr/bin/env python3
import os
import sys
import uuid
from models import User, NodeMetadata, Folder
import Crypto.Random
from client.crypto import *

ROOT_DIR = os.path.dirname(sys.modules['__main__'].__file__)


def init(user: User) -> None:
    """
    Initialize the storage "client" structure
    :param user: User object
    :return: None
    """
    if not os.path.exists(os.path.join(ROOT_DIR, "client", "storage")):
        os.mkdir(os.path.join(ROOT_DIR, "client", "storage"))
    if not os.path.exists(os.path.join(ROOT_DIR, "client", "storage", user.username)):
        os.mkdir(os.path.join(ROOT_DIR, "client", "storage", user.username))


def get_root_path_for_user(username: str) -> str:
    """
    Get the root path for a given user
    :param username: Username
    :return: str
    """
    return os.path.join(ROOT_DIR, "client", "storage", username)


def get_or_create_node_metadata(node_name: str, node_type: str, parent_folder: Folder) -> (bool, NodeMetadata):
    """
    Create a NodeMetadata object to send it to the server
    :param node_name: Node name
    :param node_type: Node type
    :param parent_folder: Parent folder
    :return: bool (if the node is new), NodeMetadata object
    """
    # Check if the node already exists
    if parent_folder.metadata.nodes is not None:
        for node in parent_folder.metadata.nodes:
            # Decrypt the node name to check if it's the same
            decrypted_node_name = xcha_cha_20_poly_1305_decrypt(node.enc_name[0], node.enc_name[1], node.enc_name[2],
                                                                parent_folder.sym_key).decode('utf-8')
            if decrypted_node_name == node_name and node.node_type == node_type:
                return False, node
    # Create a new node metadata
    nonce = Crypto.Random.get_random_bytes(24)
    _, enc_name, tag = xcha_cha_20_poly_1305_encrypt(node_name.encode('utf-8'), nonce, parent_folder.sym_key)
    vault_path = os.path.normpath(os.path.join(parent_folder.metadata.vault_path, parent_folder.metadata.uuid))
    return True, NodeMetadata(
        uuid=str(uuid.uuid4()),
        enc_name=(enc_name, nonce, tag),
        vault_path=vault_path,
        node_type=node_type,
    )


def read_file_content(file_path: str) -> bytes:
    """
    Read the content of a file
    :param file_path: File path
    :return: bytes
    """
    with open(file_path, "rb") as f:
        content = f.read()
        f.close()
        return content


def create_folder(path: str, name: str) -> bool:
    """
    Create a folder
    :param path: Path of the folder
    :param name: Name of the folder
    :return: bool
    """
    if not os.path.exists(os.path.join(path, name)):
        os.mkdir(os.path.join(path, name))
        return True
    return False
