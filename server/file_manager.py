#!/usr/bin/env python3
from models import EncryptedFile, NodeMetadata
from server.storage import *


def init_user_root_folder(folder_metadata: FolderMetadata):
    """
    Create the user folder
    :param folder_metadata: FolderMetadata object
    :return: None
    """
    # Create the user folder
    if not os.path.exists(os.path.join("server", "vault", "files", folder_metadata.owner)):
        os.mkdir(os.path.join("server", "vault", "files", folder_metadata.owner))
    if not os.path.exists(os.path.join("server", "vault", "files", folder_metadata.owner,
                                       "metadata-" + folder_metadata.owner + ".json")):
        with open(os.path.join("server", "vault", "files", folder_metadata.owner,
                               "metadata-" + folder_metadata.owner + ".json"), "w") as f:
            f.write(folder_metadata.to_json())
            f.close()


def update_file(parent_folder_metadata: FolderMetadata, new_node_metadata: NodeMetadata,
                enc_file: EncryptedFile) -> bool:
    """
    Update the folder metadata
    :param parent_folder_metadata: FolderMetadata object of the parent directory
    :param new_node_metadata: NodeMetadata object (new node)
    :param enc_file: EncryptedFile object
    :return: bool
    """
    # Update parent folder metadata
    if not set_folder_metadata(parent_folder_metadata, force=True):
        return False
    # Write the encrypted file
    return write_file(os.path.join(new_node_metadata.vault_path, new_node_metadata.uuid), enc_file.to_json())


def download_file(parent_folder_metadata: FolderMetadata, node_metadata: NodeMetadata) -> Optional[EncryptedFile]:
    """
    Download a file
    :param parent_folder_metadata: FolderMetadata object of the parent directory
    :param node_metadata: NodeMetadata object
    :return: Optional[EncryptedFile]
    """
    file_path = os.path.join(parent_folder_metadata.vault_path, parent_folder_metadata.uuid, node_metadata.uuid)
    if not os.path.exists(file_path):
        return None
    with open(file_path, "r") as f:
        content = f.read()
        f.close()
        return EncryptedFile.from_json(content)
