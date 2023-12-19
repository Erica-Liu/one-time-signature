import hashlib
import os

def hash_message(message):
    """Hashes a message using SHA-256."""
    return hashlib.sha256(message.encode()).hexdigest()

def key_generation():
    """Generates a key pair for Lamport one-time signature."""
    private_key = [[os.urandom(32) for _ in range(2)] for _ in range(256)]  # Each element is a pair of 32-byte strings
    public_key = [[hash_message(private_key[i][j]) for j in range(2)] for i in range(256)]
    return private_key, public_key

def sign(private_key, message):
    """Signs a message using Lamport one-time signature."""
    if len(message) != 256:
        raise ValueError("Message length must be 256 bits")

    signature = [private_key[i][int(message[i], 16)] for i in range(256)]
    return signature

def verify(public_key, message, signature):
    """Verifies a signature using Lamport one-time signature."""
    if len(message) != 256:
        raise ValueError("Message length must be 256 bits")

    reconstructed_hash = [hash_message(public_key[i][int(message[i], 16)]) for i in range(256)]
    return signature == reconstructed_hash

def run_lamport_signature():
    # Example usage of the Lamport one-time signature scheme
    message = "0123456789ABCDEF"  # 256-bit message in hexadecimal

    # Key generation
    private_key, public_key = key_generation()

    # Signing
    signature = sign(private_key, message)

    # Verification
    is_verified = verify(public_key, message, signature)

    # Output results
    print("Message:", message)
    print("Private Key:", private_key)
    print("Public Key:", public_key)
    print("Signature:", signature)
    print("Verification Result:", is_verified)

if __name__ == "__main__":
    run_lamport_signature()
