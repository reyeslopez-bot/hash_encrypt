"""lattice_crypto.py - A simple lattice-based cryptosystem implementation"""
import numpy as np

class LatticeCrypto:
    def __init__(self, key_size=256):
        self.key_size = key_size
        self.secret_key = self.generate_key(key_size)
        self.public_key = self.generate_key(key_size)

    def generate_key(self, size):
        # Generate a random lattice basis
        return np.random.randint(-5, 5, size=(size, size))

    def encrypt(self, plaintext):
        # Ensure plaintext length matches key size, pad with spaces if necessary
        if len(plaintext) < self.key_size:
            plaintext += ' ' * (self.key_size - len(plaintext))
        elif len(plaintext) > self.key_size:
            plaintext = plaintext[:self.key_size]

        plaintext_vector = np.array([ord(char) for char in plaintext])
        error_vector = np.random.normal(0, 1.5, self.key_size)
        return np.dot(self.public_key, plaintext_vector) + error_vector

    def decrypt(self, ciphertext):
        try:
            inv_key = np.linalg.inv(self.secret_key)
            plaintext_vector = np.dot(inv_key, ciphertext)
            print("Debug: Inverted key =", inv_key)
            print("Debug: Decrypted vector =", plaintext_vector)
            # Validating and clamping
            return ''.join([chr(int(round(min(max(char, 0), 127)))) for char in plaintext_vector])
        except np.linalg.LinAlgError:
            return "Decryption failed due to non-invertible key"

if __name__ == "__main__":
    crypto = LatticeCrypto(key_size=10)
    plaintext = "Hello, world!"
    # Pad or trim the plaintext to match the key size
    if len(plaintext) < crypto.key_size:
        plaintext += ' ' * (crypto.key_size - len(plaintext))
    elif len(plaintext) > crypto.key_size:
        plaintext = plaintext[:crypto.key_size]
    
    encrypted = crypto.encrypt(plaintext)
    decrypted = crypto.decrypt(encrypted)

    print("Original:", plaintext)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
