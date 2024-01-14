#!/usr/bin/env python3
import os
import sys

import Crypto.Random
import Crypto.PublicKey.RSA

from models import Folder, User, FolderMetadata, EncryptedFile, UserMetadata, Share
from typing import Optional
from client import file_manager as client_file_manager
from client.crypto import *
from server import api as server_api
from client import utils as client_utils


class Session:
    def __init__(self, user: User, current_folder: Folder):
        """
        Initialize the Session object
        :param user: User object
        :param current_folder: Current folder
        """
        self.user = user
        self.current_folder = current_folder
        self.parent_folders = []
        root_dir = os.path.dirname(sys.modules['__main__'].__file__)
        self.base_path = os.path.join(root_dir, "client", "storage", user.username)
        # Init the shares path with the base_path
        for share in self.user.shares:
            share.folder_path = os.path.join(self.base_path, "shares")

    def share_folder(self) -> bool:
        """
        Share a folder with another user
        :return: bool
        """
        # List the folders in the current directory
        print("Here is the list of the folders you can share:")
        dir_map = self.current_folder.list_dirs()
        if len(dir_map) == 0:
            print("No folders to share.")
            return False
        try:
            choice = int(input("Enter your choice: "))
            if 1 <= choice <= len(dir_map):
                # Get the folder (to share) data from the server
                folder_name = os.path.split(dir_map[choice])[-1]
                folder_to_share: Optional[Folder] = client_utils.get_folder_from_server(self.current_folder, self.user,
                                                                                        folder_name)
                if folder_to_share is None:
                    return False

                # Get the user to share with
                username = input("Enter the username of the user you want to share with: ")
                user_to_share_with: Optional[UserMetadata] = server_api.get_user_metadata_request(username)
                if user_to_share_with is None:
                    print("User not found.")
                    return False

                # If already shared with him
                for share in user_to_share_with.shares:
                    if share.uuid == folder_to_share.metadata.uuid:
                        print("You already shared this folder with this user.")
                        return False

                # Cipher the sym key of the folder with his public key
                shared_metadata = client_utils.encrypt_folder_for_sharing(folder_to_share, user_to_share_with)

                # Send that to the server
                return server_api.share_folder_request(shared_metadata.to_json(), user_to_share_with.to_json())
            else:
                print("Invalid choice. Please enter a valid number.")
                return False
        except ValueError:
            print("Invalid input. Please enter a number.")
            return False

    def change_directory(self) -> bool:
        """
        Change the current directory
        :return: None
        """
        # print the list of the folders in the current path
        print("Here is the list of the folders:")
        print("0. ..")
        dir_map = self.current_folder.list_dirs()  # contains full path
        # Also list the shares if in root directory
        if len(self.parent_folders) == 0:
            self.list_shares(start_index=(1 + len(dir_map)))

        try:
            choice = int(input("Enter your choice: "))
            if choice == 0:
                if self.current_folder.folder_path == self.base_path:
                    print("You are already at the root directory.")
                    return False
                if len(self.parent_folders) != 0:
                    self.current_folder = self.parent_folders.pop()
                print("You are now in the folder " + self.current_folder.folder_path)
                return True
            elif 1 <= choice <= len(dir_map):
                folder_name = os.path.split(dir_map[choice])[-1]
                # Normal folders
                new_folder = client_utils.get_folder_from_server(self.current_folder, self.user, folder_name)
                if new_folder is None:
                    return False
                self.parent_folders.append(self.current_folder)
                self.current_folder = new_folder
                print("You are now in the folder " + dir_map[choice])
                return True
            elif len(dir_map) + 1 <= choice <= len(dir_map) + len(self.user.shares) and len(self.parent_folders) == 0:
                # Shares
                share_index = choice - len(dir_map) - 1
                share: Share = self.user.shares[share_index]
                # Verify if the share folder is downloaded
                if share.name not in os.listdir(os.path.join(self.base_path, "shares")):
                    print("Please download the share first.")
                    return False
                new_folder: Folder = client_utils.get_share_folder_from_server(share, self.base_path)
                if new_folder is None:
                    return False
                self.parent_folders.append(self.current_folder)
                self.current_folder = new_folder
                print("You are now in the folder " + new_folder.folder_path)
                return True
            else:
                print("Invalid choice. Please enter a valid number.")
                return False
        except ValueError:
            print("Invalid input. Please enter a number.")
            return False

    def upload_file_folder(self) -> bool:
        """
        Ask the user which file to upload. Then upload it to the server.
        :return: bool
        """
        # List files in current directory
        print("Here is the list of the files you can upload:")
        file_map = self.current_folder.list_files()
        if len(file_map) == 0:
            return False
        try:
            choice = int(input("Enter your choice: "))
            if 1 <= choice <= len(file_map):
                # Update the parent folder with a new node
                is_new, new_node_metadata = client_file_manager.get_or_create_node_metadata(
                    node_name=os.path.split(file_map[choice])[-1],
                    node_type="file",
                    parent_folder=self.current_folder,
                )
                if is_new:
                    self.current_folder.metadata.nodes.append(new_node_metadata)
                enc_file = self.encrypt_file_content(client_file_manager.read_file_content(file_map[choice]))

                return server_api.upload_file_request(self.current_folder.metadata.to_json(),
                                                      new_node_metadata.to_json(),
                                                      enc_file.to_json())
            else:
                print("Invalid choice. Please enter a valid number.")
                return False
        except ValueError:
            print("Invalid input. Please enter a number.")
            return False

    def download_file_folder(self) -> bool:
        """
        Ask the user which file to download. Then download it from the server.
        :return: bool
        """
        # List files in current directory
        print("Here is the list of the files you can download:")
        file_names = self.list_files_folders_to_download()
        self.list_shares(start_index=(len(file_names) + 1))
        if len(file_names) == 0 and len(self.user.shares) == 0:
            print("No files to download.")
            return False
        try:
            choice = int(input("Enter your choice: "))
            if 1 <= choice <= len(file_names):
                node = self.current_folder.metadata.nodes[choice - 1]
                if node.node_type == "file":
                    # Download the file from the server
                    enc_file: EncryptedFile = server_api.download_file_request(self.current_folder.metadata.to_json(),
                                                                               node.to_json())
                    if enc_file is None:
                        return False
                    # Decrypt the file and write it in the current folder
                    with (open(os.path.join(self.current_folder.folder_path, file_names[choice]), "wb")) as f:
                        f.write(self.decrypt_file_content(enc_file))
                        f.close()
                    return True
                elif node.node_type == "folder":
                    # Get the folder metadata from the server
                    downloaded_folder: Folder = client_utils.get_folder_from_server(self.current_folder, self.user,
                                                                                    file_names[choice])
                    if downloaded_folder is None:
                        return False
                    # Create the folder
                    return client_file_manager.create_folder_from_folder_object(downloaded_folder)
                # If node type is not file or folder
                return False
            elif len(file_names) + 1 <= choice <= len(file_names) + len(self.user.shares):
                # Download the share from the server
                share_index = choice - len(file_names) - 1
                share: Share = self.user.shares[share_index]
                # Get the folder metadata from the server
                downloaded_folder: Folder = client_utils.get_share_folder_from_server(share, self.base_path)
                if downloaded_folder is None:
                    return False
                # Create the folder
                return client_file_manager.create_folder_from_folder_object(downloaded_folder)
            else:
                print("Invalid choice. Please enter a valid number.")
            return False

        except ValueError:
            print("Invalid input. Please enter a number.")
        return False

    def list_files_folders_to_download(self) -> dict[int, str]:
        """
        List the file and folder names in the current folder
        :return: Map of index to file or folder names (only names without path)
        """
        if self is None:
            raise Exception("No user connected")
        file_map = {}
        index = 1
        for node in self.current_folder.metadata.nodes:
            name = xcha_cha_20_poly_1305_decrypt(node.enc_name[0], node.enc_name[1], node.enc_name[2],
                                                 self.current_folder.sym_key).decode('utf-8')
            file_map[index] = name
            print(f"{index}. {node.node_type.upper()} : {name}")
            index += 1
        return file_map

    def create_folder(self, folder_name: str) -> bool:
        """
        Create a folder
        :param folder_name: New folder name
        :return: bool
        """
        if folder_name == "shares":
            print("The folder name 'shares' is reserved. Please choose another name.")
            return False
        # Update the parent folder with a new node
        is_new, new_node_metadata = client_file_manager.get_or_create_node_metadata(
            node_name=folder_name,
            node_type="folder",
            parent_folder=self.current_folder,
        )
        if not is_new:
            print("Folder already exists")
            return False
        self.current_folder.metadata.nodes.append(new_node_metadata)
        client_file_manager.create_folder(self.current_folder.folder_path, folder_name)
        # Generate new sym key for the folder created
        nonce = Crypto.Random.get_random_bytes(24)
        sym_key = Crypto.Random.get_random_bytes(KEY_LENGTH_BYTES)
        _, encrypted_sym_key, tag = xcha_cha_20_poly_1305_encrypt(sym_key, nonce, self.current_folder.sym_key)
        new_folder_metadata = FolderMetadata(
            uuid=new_node_metadata.uuid,
            enc_name=new_node_metadata.enc_name,
            enc_sym_key=(encrypted_sym_key, nonce, tag),
            vault_path=os.path.join(self.current_folder.metadata.vault_path, self.current_folder.metadata.uuid),
            owner=self.user.username,
            nodes=[],
        )
        # Create the folder in the server
        return server_api.create_folder_request(self.current_folder.metadata.to_json(), new_folder_metadata.to_json(),
                                                new_node_metadata.to_json())

    def list_shares(self, start_index: int):
        """
        List the shares of the connected user
        :param start_index: Index to start the list
        :return: None
        """
        if len(self.user.shares) == 0:
            print("You have no shares.")
            return
        i = start_index
        print("Here is the list of your shares:")
        for share in self.user.shares:
            print(f"{i}. {share.name}")
            i += 1

    def encrypt_file_content(self, content: bytes) -> (bytes, bytes, bytes):
        """
        Encrypt the content of a file
        :param content: Content of the file as bytes
        :return: EncryptedFile object
        """
        nonce = Crypto.Random.get_random_bytes(24)
        _, enc_content, tag = xcha_cha_20_poly_1305_encrypt(content, nonce, self.current_folder.sym_key)
        return EncryptedFile(
            (enc_content, nonce, tag)
        )

    def decrypt_file_content(self, enc_file: EncryptedFile) -> bytes:
        """
        Decrypt the content of a file
        :param enc_file: EncryptedFile object
        :return: Content of the file as bytes
        """
        return xcha_cha_20_poly_1305_decrypt(enc_file.enc_content[0], enc_file.enc_content[1], enc_file.enc_content[2],
                                             self.current_folder.sym_key)


def set_session_user(session: Session):
    """
    Set the session of the connected user
    :param session: Session object
    :return: None
    """
    global SESSION_USER
    SESSION_USER = session


def get_session_user() -> Optional[Session]:
    """
    Get the session of the connected user
    :return: Session object or None
    """
    global SESSION_USER
    return SESSION_USER


# Contain the session of the connected user (User object or None if not connected)
SESSION_USER: Optional[Session] = None
