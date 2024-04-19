"""encrypt - Encrypt and decrypt messages using Fernet symmetric encryption."""
import os
from cryptography.fernet import Fernet, InvalidToken
import logging
logging.basicConfig(filename='encryption.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Encrypt:
# Generate a key and instantiate a Fernet instance
    @staticmethod
    def generate_key():
        """generate_key - Generate a key for encryption."""
        key = Fernet.generate_key()
        with open('key.key', 'wb') as key_file:
            key_file.write(key)
        return key

    @staticmethod
    def load_key():
        """load_key - Load the encryption key from a file."""
        return open('key.key', 'rb').read()

    @staticmethod
    def encrypt_file(file_path, key):
        """Encrypt a file using the key."""
        if not file_path.endswith('.enc'):
            file_path += '.enc'  # Ensure the file is saved with the .enc extension
        if not os.path.exists(file_path):
            return f"Error: The file '{file_path}' does not exist.", False
        f = Fernet(key)
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        encrypted_file_path = file_path
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)
        return encrypted_file_path, True

    def decrypt_file(file_path, key):
        """Decrypt a file using the key."""
        print(f"Received file path for decryption: {file_path}")  # Debugging output
        if not isinstance(file_path, str) or not file_path.endswith('.enc'):
            return f"Error: The file path must be a string and end with '.enc', given path: {file_path}", False
        if not os.path.exists(file_path):
            return f"Error: The file '{file_path}' does not exist.", False

        f = Fernet(key)
        try:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = f.decrypt(encrypted_data)
            decrypted_file_path = file_path[:-4]  # Remove the '.enc' extension
            with open(decrypted_file_path, 'wb') as file:
                file.write(decrypted_data)
            return decrypted_file_path, True
        except InvalidToken:
            return "Error: Decryption failed. Invalid encryption key or file has been corrupted.", False

    @staticmethod
    def encrypt_message(key, message):
        """encrypt_message - Encrypt a message using the key."""
        f = Fernet(key)
        message = message.strip().encode()
        encrypted_message = f.encrypt(message)
        return encrypted_message.decode()

    @staticmethod
    def decrypt_message(key, encrypted_message):
        f = Fernet(key)
        try:
            decrypted_message = f.decrypt(encrypted_message.encode()).decode()
            return decrypted_message  # Directly return the message
        except (InvalidToken, ValueError) as e:
            print("Error decrypting message:", str(e))
            return None

    @staticmethod
    def show_menu_and_get_choice():
        """Display the menu and get the user's choice."""
        print("\n1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Encrypt a file")
        print("4. Decrypt a file")
        print("5. Exit")
        choice = input("Enter your choice: ")
        while choice not in ['1', '2', '3', '4', '5']:
            print("Invalid choice. Please try again.")
            choice = input("Enter your choice: ")
        return choice

    @staticmethod
    def ask_if_another_operation():
        """Ask the user if they want to perform another operation."""
        answer = input("Do you want to perform another operation? (y/n): ")
        return answer.lower() == 'y'


def main():
    logging.info("Starting encryption tool.")
    try:
        key = Encrypt.load_key()
        logging.info("Encryption key loaded successfully.")
    except FileNotFoundError:
        logging.error("No encryption key found. Generating a new one.")
        key = Encrypt.generate_key()
        logging.info("New key generated and saved.")

    while True:
        choice = Encrypt.show_menu_and_get_choice()
        if choice == '1':
            message = input("Enter the message to encrypt: ")
            encrypted_message = Encrypt.encrypt_message(key, message)
            print(f"Encrypted message: {encrypted_message}")
        elif choice == '2':
            encrypted_message = input("Enter the message to decrypt: ")
            decrypted_message = Encrypt.decrypt_message(key, encrypted_message)
            if decrypted_message:
                print(f"Decrypted message: {decrypted_message}")
            else:
                print("Error decrypting message.")
        elif choice == '3':
            file_path = input("Enter the file path to encrypt: ").strip()
            encrypted_file_path, success = Encrypt.encrypt_file(key, file_path)
            if success:
                print(f"File encrypted successfully as {encrypted_file_path}")
            else:
                print("Error encrypting file.")
        elif choice == '4':
            file_path = input("Enter the file path to decrypt: ").strip()
            print(f"Attempting to decrypt file: {file_path}")  # Debugging output
            decrypted_file_path, success = Encrypt.decrypt_file(file_path, key)
            if success:
                print(f"File decrypted successfully as {decrypted_file_path}")
            else:
                print(f"Decryption error: {decrypted_file_path}")
        elif choice == '5':
            print("Exiting script.")
            break
        else:
            print("Invalid choice. Please try again.")

        if not Encrypt.ask_if_another_operation():
            break

if __name__ == "__main__":
    main()