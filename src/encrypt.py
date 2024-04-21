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
        """Attempt to load the encryption key from a file, generate if not found."""
        try:
            with open('key.key', 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            # Generate a new key if not found
            return Encrypt.generate_key()

    @staticmethod
    def encrypt_file(file_path, key):
        if not os.path.isfile(file_path):
            logging.error(f"File not found: {file_path}")
            return "Error: File does not exist.", False
        encrypted_file_path = file_path + '.enc'
        try:
            with open(file_path, 'rb') as file:
                data = file.read()
            logging.debug(f"Read data from {file_path}")
            f = Fernet(key)
            encrypted_data = f.encrypt(data)
            logging.debug("Data encrypted")
            with open(encrypted_file_path, 'wb') as file:
                file.write(encrypted_data)
            logging.info(f"File encrypted successfully: {encrypted_file_path}")
            return f"File encrypted successfully: {encrypted_file_path}", True
        except Exception as e:
            logging.error(f"Failed to encrypt file due to: {str(e)}")
            return f"Error encrypting file: {e}", False

    @staticmethod
    def decrypt_file(file_path, key):
        if not file_path.endswith('.enc') or not os.path.isfile(file_path):
            return "Error: Encrypted file does not exist.", False
        try:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            f = Fernet(key)
            data = f.decrypt(encrypted_data)
            decrypted_file_path = file_path[:-4]  # removing '.enc'
            with open(decrypted_file_path, 'wb') as file:
                file.write(data)
            return f"File decrypted successfully: {decrypted_file_path}", True
        except Exception as e:
            return f"Error decrypting file: {e}", False

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

    @staticmethod
    def list_encrypted_files(directory):
        """List all .enc files in a given directory."""
        try:
            files = os.listdir(directory)
            enc_files = [file for file in files if file.endswith('.enc')]
            if not enc_files:
                print("No encrypted files found in the directory.")
            else:
                print("Encrypted files:")
                for file in enc_files:
                    print(file)
        except FileNotFoundError:
            print(f"Directory not found: {directory}")
        except Exception as e:
            print(f"An error occurred: {e}")

def main():
    logging.info("Starting encryption tool.")
    try:
        key = Encrypt.load_key()
        logging.info("Encryption key loaded successfully.")
    except FileNotFoundError:
        logging.error("No encryption key found. Generating a new one.")
        key = Encrypt.generate_key()
        logging.info("New key generated and saved.")

    try:
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
                encrypted_file_path, success = Encrypt.encrypt_file(file_path, key)
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
    except KeyboardInterrupt:
        print("\nScript interrupted by user. Exiting...")
        logging.info("Script interrupted by user.")

if __name__ == "__main__":
    main()
