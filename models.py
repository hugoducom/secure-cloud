#!/usr/bin/env python3
import json
import os
import base64


class UserMetadata:
    def __init__(self, username: str, password_hash: bytes, encrypted_sym_key: (bytes, bytes, bytes),
                 encrypted_private_key: (bytes, bytes, bytes), public_key: bytes):
        """
        User metadata (encrypted)
        :param username: Username
        :param password_hash: Password hash
        :param encrypted_sym_key: Tuple of (encrypted symmetric key, nonce, tag)
        :param encrypted_private_key: Tuple of (encrypted private key, nonce, tag)
        :param public_key: Public key
        """
        self.username = username
        self.password_hash = password_hash
        self.encrypted_sym_key = encrypted_sym_key
        self.encrypted_private_key = encrypted_private_key
        self.public_key = public_key

    def to_json(self) -> str:
        """
        Convert the object to a JSON string
        :return: JSON string
        """
        return json.dumps({
            "username": self.username,
            "password_hash": base64.b64encode(self.password_hash).decode('utf-8'),
            "encrypted_sym_key": {
                "cipher": base64.b64encode(self.encrypted_sym_key[0]).decode('utf-8'),
                "nonce": base64.b64encode(self.encrypted_sym_key[1]).decode('utf-8'),
                "tag": base64.b64encode(self.encrypted_sym_key[2]).decode('utf-8'),
            },
            "encrypted_private_key": {
                "cipher": base64.b64encode(self.encrypted_private_key[0]).decode('utf-8'),
                "nonce": base64.b64encode(self.encrypted_private_key[1]).decode('utf-8'),
                "tag": base64.b64encode(self.encrypted_private_key[2]).decode('utf-8'),
            },
            "public_key": base64.b64encode(self.public_key).decode('utf-8'),
        })

    @staticmethod
    def from_json(json_data: str) -> 'UserMetadata':
        metadata_object = json.loads(json_data)
        return UserMetadata(
            metadata_object["username"],
            base64.b64decode(metadata_object["password_hash"].encode('utf-8')),
            (base64.b64decode(metadata_object["encrypted_sym_key"]["cipher"].encode('utf-8')),
             base64.b64decode(metadata_object["encrypted_sym_key"]["nonce"].encode('utf-8')),
             base64.b64decode(metadata_object["encrypted_sym_key"]["tag"].encode('utf-8'))),
            (base64.b64decode(metadata_object["encrypted_private_key"]["cipher"].encode('utf-8')),
             base64.b64decode(metadata_object["encrypted_private_key"]["nonce"].encode('utf-8')),
             base64.b64decode(metadata_object["encrypted_private_key"]["tag"].encode('utf-8'))),
            base64.b64decode(metadata_object["public_key"].encode('utf-8')),
        )


class User:
    def __init__(self, username: str, stretched_master_key: bytes, sym_key: bytes, private_key: bytes,
                 public_key: bytes):
        """
        User object (decrypted)
        :param username: Username
        :param stretched_master_key: Stretched master key
        :param sym_key: Symmetric key
        :param private_key: Private key
        :param public_key: Public key
        """
        self.username = username
        self.stretched_master_key = stretched_master_key
        self.sym_key = sym_key
        self.private_key = private_key
        self.public_key = public_key

    def to_json(self):
        """
        Convert the object to a JSON string
        :return: JSON string
        """
        return json.dumps({
            "username": self.username,
            "stretched_master_key": base64.b64encode(self.stretched_master_key).decode('utf-8'),
            "sym_key": base64.b64encode(self.sym_key).decode('utf-8'),
            "private_key": base64.b64encode(self.private_key).decode('utf-8'),
            "public_key": base64.b64encode(self.public_key).decode('utf-8'),
        })


class FolderMetadata:
    def __init__(self, uuid: str, enc_name: (bytes, bytes, bytes), enc_sym_key: (bytes, bytes, bytes), vault_path: str,
                 owner: str,
                 nodes: list['NodeMetadata']):
        """
        Folder metadata (encrypted)
        :param uuid: UUID of the folder
        :param enc_name: Tuple of (encrypted name, nonce, tag)
        :param enc_sym_key: Tuple of (encrypted symmetric key, nonce, tag)
        :param vault_path: Vault path (without UUID)
        :param owner: Owner username
        :param nodes: List of nodes (files or folders)
        """
        self.uuid = uuid
        self.enc_name = enc_name
        self.vault_path = vault_path
        self.enc_sym_key = enc_sym_key
        self.owner = owner
        self.nodes = nodes

    def to_json(self) -> str:
        """
        Convert the object to a JSON string
        :return: JSON string
        """
        return json.dumps({
            "uuid": self.uuid,
            "enc_name": {
                "cipher": base64.b64encode(self.enc_name[0]).decode('utf-8'),
                "nonce": base64.b64encode(self.enc_name[1]).decode('utf-8'),
                "tag": base64.b64encode(self.enc_name[2]).decode('utf-8'),
            },
            "enc_sym_key": {
                "cipher": base64.b64encode(self.enc_sym_key[0]).decode('utf-8'),
                "nonce": base64.b64encode(self.enc_sym_key[1]).decode('utf-8'),
                "tag": base64.b64encode(self.enc_sym_key[2]).decode('utf-8'),
            },
            "vault_path": self.vault_path,
            "owner": self.owner,
            "nodes": [node.to_json() for node in self.nodes],
        })

    @staticmethod
    def from_json(json_data: str) -> 'FolderMetadata':
        metadata_object = json.loads(json_data)
        return FolderMetadata(
            metadata_object["uuid"],
            (base64.b64decode(metadata_object["enc_name"]["cipher"].encode('utf-8')),
             base64.b64decode(metadata_object["enc_name"]["nonce"].encode('utf-8')),
             base64.b64decode(metadata_object["enc_name"]["tag"].encode('utf-8'))),
            (base64.b64decode(metadata_object["enc_sym_key"]["cipher"].encode('utf-8')),
             base64.b64decode(metadata_object["enc_sym_key"]["nonce"].encode('utf-8')),
             base64.b64decode(metadata_object["enc_sym_key"]["tag"].encode('utf-8'))),
            metadata_object["vault_path"],
            metadata_object["owner"],
            [NodeMetadata.from_json(node) for node in metadata_object["nodes"]],
        )


class Folder:
    def __init__(self, folder_name: str, folder_path: str, sym_key: bytes, nodes: list['NodeMetadata']):
        """
        Folder metadata (decrypted)
        :param folder_name: Folder name
        :param folder_path: Entire folder path
        :param sym_key: Symmetric key
        :param nodes: List of nodes as list of NodeMetadata (files or folders)
        """
        self.folder_name = folder_name
        self.folder_path = folder_path
        self.sym_key = sym_key
        self.nodes = nodes

    def list_dirs(self) -> dict[int, str]:
        """
        List the directories in the current directory of the connected user
        :return: Map of index to directory path
        """
        print("0. ..")
        i_dir = 1
        dir_map = {}
        for f in os.listdir(self.folder_path):
            if os.path.isdir(os.path.join(self.folder_path, f)):
                dir_map[i_dir] = os.path.join(self.folder_path, f)
                print(f"{i_dir}. {f}")
        return dir_map

    def list_files(self) -> dict[int, str]:
        """
        List the files in the current directory of the connected user
        :return: Map of index to file path
        """
        i_files = 1
        file_map = {}
        print(f"Current path : {self.folder_path}")
        for f in os.listdir(self.folder_path):
            if os.path.isfile(os.path.join(self.folder_path, f)):
                file_map[i_files] = os.path.join(self.folder_path, f)
                print("{}. {}".format(i_files, f))
                i_files += 1
        return file_map

    def to_json(self):
        """
        Convert the object to a JSON string
        :return: JSON string
        """
        return json.dumps({
            "folder_name": self.folder_name,
            "folder_path": self.folder_path,
            "sym_key": base64.b64encode(self.sym_key).decode('utf-8'),
            "nodes": [node.to_json() for node in self.nodes],
        })


class NodeMetadata:
    def __init__(self, uuid: str, enc_name: (bytes, bytes, bytes), vault_path: str, node_type: str):
        """
        Node metadata (encrypted)
        :param uuid: UUID of the node
        :param enc_name: Tuple of (encrypted name, nonce, tag)
        :param vault_path: Vault path
        :param node_type: Node type ('file' or 'folder')
        """
        self.uuid = uuid
        self.enc_name = enc_name
        self.vault_path = vault_path
        self.node_type = node_type

    def to_json(self):
        """
        Convert the object to a JSON string
        :return: JSON string
        """
        return json.dumps({
            "uuid": self.uuid,
            "enc_name": {
                "cipher": base64.b64encode(self.enc_name[0]).decode('utf-8'),
                "nonce": base64.b64encode(self.enc_name[1]).decode('utf-8'),
                "tag": base64.b64encode(self.enc_name[2]).decode('utf-8'),
            },
            "vault_path": self.vault_path,
            "node_type": self.node_type,
        })

    @staticmethod
    def from_json(json_data: str) -> 'NodeMetadata':
        metadata_object = json.loads(json_data)
        return NodeMetadata(
            metadata_object["uuid"],
            (base64.b64decode(metadata_object["enc_name"]["cipher"].encode('utf-8')),
             base64.b64decode(metadata_object["enc_name"]["nonce"].encode('utf-8')),
             base64.b64decode(metadata_object["enc_name"]["tag"].encode('utf-8'))),
            metadata_object["vault_path"],
            metadata_object["node_type"],
        )