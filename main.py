#!/usr/bin/env python3
from getpass import getpass
from client import auth as client_auth
from client import session as client_session
from server import storage as server_storage
from client import file_manager as client_file_manager


def main():
    # Initialize the storage
    server_storage.init()

    # Simple menu picker
    print("Welcome to the secure cloud client!")

    while True:
        print("""
        1. Login
        2. Register
        3. Exit
        """)
        choice = input("Enter your choice: ")
        if choice == "1":
            username = input("Enter your username: ")
            password = getpass("Enter your password: ")
            logged_in = client_auth.login(username, password)
            if logged_in:
                print("Welcome " + username)
                session = client_session.get_session_user()
                # Init the directory
                client_file_manager.init(session.user)
                print("Files storage path : " + client_session.get_session_user().base_path)
                break
            else:
                print("Wrong username or password")

        elif choice == "2":
            username = input("Enter your new username: ")
            password = getpass("Enter your new password: ")
            if client_auth.register(username, password):
                print("User registered successfully")
            else:
                print("Something went wrong. Please try again.")

        elif choice == "3":
            print("Goodbye!")
            exit(0)

    while True:
        print("""
        DISCLAIMER : Please do not create directories directly from your file system.
        Create them with the option 6.
        """)
        print("""
        1. Change directory
        2. List files
        3. Download file/folder
        4. Upload file
        5. Share folder
        6. Create folder
        7. Change password
        8. Exit
        """)
        choice = input("Enter your choice: ")
        if choice == "1":
            print("Change directory")
            client_session.get_session_user().change_directory()
        elif choice == "2":
            print("List files")
            client_session.get_session_user().current_folder.list_files()
        elif choice == "3":
            print("Download file/folder")
            if not client_session.get_session_user().download_file_folder():
                print("Something went wrong. Please try again.")
            else:
                print("File or folder downloaded successfully")
        elif choice == "4":
            print("Upload file")
            if not client_session.get_session_user().upload_file_folder():
                print("Something went wrong. Please try again.")
            else:
                print("File uploaded successfully")
        elif choice == "5":
            print("Share folder")
            if not client_session.get_session_user().share_folder():
                print("Something went wrong. Please try again.")
            else:
                print("Folder shared successfully")
        elif choice == "6":
            print("Create folder")
            folder_name = input("Enter the folder name: ")
            if not client_session.get_session_user().create_folder(folder_name):
                print("Something went wrong. Please try again.")
            else:
                print("Folder created successfully")
        elif choice == "7":
            print("Change password")
            old_password = getpass("Enter your old password: ")
            new_password = getpass("Enter your new password: ")
            if client_auth.change_password(client_session.get_session_user().user.username, old_password, new_password):
                print("Password changed successfully")
            else:
                print("Something went wrong. Please try again.")
        elif choice == "8":
            print("Goodbye!")
            exit(0)
        else:
            print("Not a valid choice. Please try again")


if __name__ == '__main__':
    main()
