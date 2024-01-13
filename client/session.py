#!/usr/bin/env python3
import os
import sys
from models import Folder, User
from typing import Optional


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
                return True
            else:
                print("Invalid choice. Please enter a valid number.")
                return False
        except ValueError:
            print("Invalid input. Please enter a number.")
            return False

    @staticmethod
    def logout():
        """
        Logout the connected user
        :return: None
        """
        global SESSION_USER
        SESSION_USER = None


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
