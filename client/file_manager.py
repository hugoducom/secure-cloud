#!/usr/bin/env python3
import os
import sys
from models import User

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
