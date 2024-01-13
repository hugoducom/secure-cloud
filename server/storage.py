#!/usr/bin/env python3
import os
import sys
from models import UserMetadata, FolderMetadata
from typing import Optional

ROOT_DIR = os.path.dirname(sys.modules['__main__'].__file__)


def init():
    """
    Initialize the storage "server" structure
    :return: None
    """
    if not os.path.exists(os.path.join(ROOT_DIR, "server", "vault")):
        os.mkdir(os.path.join(ROOT_DIR, "server", "vault"))
    if not os.path.exists(os.path.join(ROOT_DIR, "server", "vault", "user_metadata")):
        os.mkdir(os.path.join(ROOT_DIR, "server", "vault", "user_metadata"))
    if not os.path.exists(os.path.join(ROOT_DIR, "server", "vault", "files")):
        os.mkdir(os.path.join(ROOT_DIR, "server", "vault", "files"))


def set_folder_metadata(folder_metadata: FolderMetadata, force: bool = False) -> bool:
    """
    Set the folder metadata for a given folder
    :param folder_metadata: FolderMetadata object
    :param force: Force the replacement of the file
    :return: bool
    """
    path = os.path.join(folder_metadata.vault_path, "metadata-" + folder_metadata.uuid + ".json")
    if os.path.exists(path) and not force:
        return False
    # Create the metadata file
    with open(path, "w") as f:
        f.write(folder_metadata.to_json())
        f.close()
        return True


def get_folder_metadata(folder_path, folder_uuid) -> Optional[FolderMetadata]:
    """
    Get the folder metadata for a given folder
    :param folder_path: The path of the folder
    :param folder_uuid: The uuid of the folder
    :return: FolderMetadata object or None
    """
    path = os.path.join(folder_path, "metadata-" + folder_uuid + ".json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        content = f.read()
        f.close()
        return FolderMetadata.from_json(content)


def set_user_metadata(user_metadata: UserMetadata, force: bool = False) -> bool:
    """
    Set the user metadata for a given user
    :param user_metadata: UserMetadata object
    :param force: Force the replacement of the file
    :return: bool
    """
    if os.path.exists(
            os.path.join(ROOT_DIR, "server", "vault", "user_metadata", user_metadata.username + ".json")) and not force:
        return False
    # Create the file
    with open(os.path.join(ROOT_DIR, "server", "vault", "user_metadata", user_metadata.username + ".json"), "w") as f:
        f.write(user_metadata.to_json())
        f.close()
        return True


def get_user_metadata(username: str) -> Optional[UserMetadata]:
    """
    Get the user metadata for a given user
    :param username: The username of the user
    :return: UserMetadata object or None
    """
    if not os.path.exists(os.path.join(ROOT_DIR, "server", "vault", "user_metadata", username + ".json")):
        return None
    with open(os.path.join(ROOT_DIR, "server", "vault", "user_metadata", username + ".json"), "r") as f:
        content = f.read()
        f.close()
        return UserMetadata.from_json(content)
