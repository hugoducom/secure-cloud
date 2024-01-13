#!/usr/bin/env python3
import os
from models import FolderMetadata


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
