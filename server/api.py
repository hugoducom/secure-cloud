#!/usr/bin/env python3
from server.storage import *
from server.crypto import *
from models import UserMetadata, Folder
from server.file_manager import *


def login_request(username: str, password_hash: bytes) -> Optional[UserMetadata]:
    """
    Login a user
    :param username: Username
    :param password_hash: Password hash
    :return: Optional[UserMetadata]
    """
    user_metadata = get_user_metadata(username)

    if user_metadata is None:
        return None

    if not verify_password_hash(user_metadata.password_hash, password_hash):
        return None

    return user_metadata


def register_request(user_metadata: str, root_metadata: str) -> bool:
    """
    Register a new user
    :param user_metadata: JSON object representing UserMetadata
    :param root_metadata: JSON object representing FolderMetadata
    :return: bool
    """
    user_metadata = UserMetadata.from_json(user_metadata)
    root_metadata = FolderMetadata.from_json(root_metadata)
    # Set the vault path
    root_metadata.vault_path = os.path.join(ROOT_DIR, "server", "vault", "files")
    # Init his root folder
    init_user_root_folder(root_metadata)
    # Hash the password with a random salt
    user_metadata.password_hash = argon2(user_metadata.password_hash)
    return set_user_metadata(user_metadata)


def upload_file_request(username, folder_metadata, file_metadata):
    pass


def get_user_root_folder_request(username: str) -> Optional[FolderMetadata]:
    """
    Get the root folder of a user
    :param username: Username
    :return: FolderMetadata object
    """
    return get_folder_metadata(os.path.join(ROOT_DIR, "server", "vault", "files", username), username)


def change_password_request(username: str, old_password_hash: bytes, new_password_hash: bytes,
                            new_encrypted_sym_key: (bytes, bytes, bytes)) -> bool:
    """
    Change the password of a user
    :param username: Username as string
    :param old_password_hash: Old password hash as bytes string
    :param new_password_hash: New password hash as bytes string
    :param new_encrypted_sym_key: Tuple of (encrypted symmetric key, nonce, tag) each as bytes string
    :return: bool
    """
    user_metadata = get_user_metadata(username)

    if user_metadata is None:
        return False

    if not verify_password_hash(user_metadata.password_hash, old_password_hash):
        return False

    user_metadata.password_hash = argon2(new_password_hash)
    user_metadata.encrypted_sym_key = new_encrypted_sym_key
    # No need to change private key because the sym key is the same

    return set_user_metadata(user_metadata, force=True)
