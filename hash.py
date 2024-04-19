"""hash_encrypt.py: Generate a salted and peppered hash from input string using PBKDF2."""
import argparse
import os
import base64
import configparser
import logging
from contextlib import contextmanager
from argon2 import PasswordHasher, Type
import argon2
from resources import config_file
# Setup logging
logging.basicConfig(filename='hashing.log', level=logging.DEBUG, filemode='w',
                    format='%(asctime)s - %(levelname)s - %(message)s')

logging.info("Logging initialized.")

# Context manager for logging start and end of a block of code
@contextmanager
def log_context(description):
    """log_context - Context manager for logging start and end of a block of code."""
    logging.debug("Start: %s", description)
    try:
        yield
    finally:
        logging.debug("End: %s", description)
        
def load_config():
    """load_config - Load the configuration from the config file."""
    logging.debug("Loading configuration from %s", config_file)
    config = configparser.ConfigParser()
    config.read(config_file)
    if 'ARGON2' in config:
        try:
            memory_cost = config['ARGON2'].getint('memory_cost')
            iterations = config['ARGON2'].getint('iterations')
            parallelism = config['ARGON2'].getint('parallelism')
            logging.info("Loaded configuration: memory_cost=%s, iterations=%s, parallelism=%s", memory_cost, iterations, parallelism)
            return memory_cost, iterations, parallelism
        except ValueError as e:
            logging.error("Configuration error: %s", e)
            raise ValueError("Configuration error: %s" % e) from e
    else:
        logging.warning("No configuration found, using defaults")
    return 1024, 2, 2  # Default values

def create_password_hasher(memory_cost, iterations, parallelism):
    """create_password_hasher - Create a PasswordHasher object with the specified parameters."""
    logging.debug("Creating PasswordHasher with memory_cost=%s, iterations=%s, parallelism=%s", memory_cost, iterations, parallelism)
    return PasswordHasher(memory_cost=memory_cost, time_cost=iterations, parallelism=parallelism, type=Type.ID)

def prepare_input(input_string, pepper, context="hashing"):
    """Prepare the input string for hashing by encoding and combining with the pepper."""
    if context == "hashing":
        logging.debug("Preparing input string for hashing")
    elif context == "validating":
        logging.debug("Preparing input string for validation")
    
    if not input_string.strip():
        raise ValueError("Input string must not be empty.")
    return input_string.encode() + base64.b64encode(pepper)

def hash_string(input_string, pepper, ph):
    """Hash the input string with the specified pepper using the PasswordHasher object."""
    logging.debug("Hashing input string")
    combined_input = prepare_input(input_string, pepper, context="hashing")
    hashed_input = ph.hash(combined_input)
    logging.info("Hashed input successfully")
    return hashed_input

def validate_input_string(input_string, hash_digest, pepper, ph):
    """Validate the input string against the hash digest using the PasswordHasher object."""
    logging.debug("Validating input string")
    combined_input = prepare_input(input_string, pepper, context="validating")
    try:
        ph.verify(hash_digest, combined_input)
        logging.info("Validation successful")
        return True
    except argon2.exceptions.VerifyMismatchError as e:
        logging.error("Validation failed: %s", e)
        return False

def main():
    """main - Main function for the script."""
    logging.info("Starting script")
    parser = argparse.ArgumentParser(description='Generate a salted and peppered hash from input string using Argon2.')
    parser.add_argument('input_string', nargs='?', help='String to hash', default='')
    parser.add_argument('--pepper', type=lambda p: base64.b64encode(os.urandom(16)), default=base64.b64encode(os.urandom(16)), help='Secret pepper for additional security')

    args = parser.parse_args()
    input_string = args.input_string if args.input_string else input("Enter a string to hash: ")

    try:
        memory_cost, iterations, parallelism = load_config()
        ph = create_password_hasher(memory_cost, iterations, parallelism)
        hash_digest = hash_string(input_string, args.pepper, ph)
        if validate_input_string(input_string, hash_digest, args.pepper, ph):
            print("Hashing successful. Check logs for details.")
        else:
            print("Hash validation failed.")
    except ValueError as e:
        logging.error("A ValueError occurred: %s", e)
        print(f"ValueError: {e}")
    except argon2.exceptions.VerifyMismatchError as e:
        logging.error("A VerifyMismatchError occurred: %s", e)
        print(f"VerifyMismatchError: {e}")

if __name__ == "__main__":
    main()
