#!/usr/bin/env python3
import os
import sys

import Crypto.Random

from models import Folder, User, FolderMetadata, EncryptedFile
from typing import Optional
from client import file_manager as client_file_manager
from client.crypto import *
from server import api as server_api


class Session:
    def __init__(self, user: User, current_folder: Folder):
        """
        Initialize the Session object
        :param user: User object
        :param current_folder: Current folder
        """
        self.user = user
        self.current_folder = current_folder
        root_dir = os.path.dirname(sys.modules['__main__'].__file__)
        self.base_path = os.path.join(root_dir, "client", "storage", user.username)

    def change_directory(self) -> bool:
        """
        Change the current directory
        :return: None
        """
        # print the list of the folders in the current path
        print("Here is the list of the folders:")
        dir_map = self.current_folder.list_dirs()

        try:
            choice = int(input("Enter your choice: "))
            if choice == 0:
                if self.current_folder.folder_path == self.base_path:
                    print("You are already at the root directory.")
                    return False
                # TODO change current_folder (dir_map contains full path)
                return True
            elif 1 <= choice <= len(dir_map):
                # TODO change current_folder (dir_map contains full path)

                print("You are now in the folder " + dir_map[choice])
                return True
            else:
                print("Invalid choice. Please enter a valid number.")
                return False
        except ValueError:
            print("Invalid input. Please enter a number.")
            return False

    def upload_file(self) -> bool:
        """
        Ask the user which file to upload. Then upload it to the server.
        :return: bool
        """
        # List files in current directory
        print("Here is the list of the files you can upload:")
        file_map = self.current_folder.list_files()
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

    def download_file(self) -> bool:
        """
        Ask the user which file to download. Then download it from the server.
        :return: bool
        """
        # List files in current directory
        print("Here is the list of the files you can download:")
        file_names = self.list_file_names()
        if len(file_names) == 0:
            print("No files to download.")
            return False
        try:
            choice = int(input("Enter your choice: "))
            if 1 <= choice <= len(file_names):
                enc_file: EncryptedFile = server_api.download_file_request(self.current_folder.metadata.to_json(),
                                                                           self.current_folder.metadata.nodes[
                                                                               choice - 1].to_json())
                if enc_file is None:
                    return False

                with (open(os.path.join(self.current_folder.folder_path, file_names[choice]), "wb")) as f:
                    f.write(self.decrypt_file_content(enc_file))
                    f.close()

                return True
            else:
                print("Invalid choice. Please enter a valid number.")
            return False

        except ValueError:
            print("Invalid input. Please enter a number.")
        return False

    def list_file_names(self) -> dict[int, str]:
        """
        List the file names in a folder
        :return: Map of index to file names (only names without path)
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
        :param folder_name: Folder name
        :return: bool
        """
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

    @staticmethod
    def logout():
        """
        Logout the connected user
        :return: None
        """
        global SESSION_USER
        SESSION_USER = None

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
