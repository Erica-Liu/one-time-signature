import hashlib
import os
import sys

def hash_message(message):
    """Hashes a message using SHA-256."""
    return hashlib.sha256(message).digest()

def key_generation():
    """Generates a key pair for Lamport one-time signature."""
    private_key = [[os.urandom(32) for _ in range(2)] for _ in range(256)]  # Each element is a pair of 32-byte strings
    public_key = [[hash_message(private_key[i][j]) for j in range(2)] for i in range(256)]
    return private_key, public_key

def sign(private_key, message):
    """Signs a message using Lamport one-time signature."""

    signature = [private_key[i][int.from_bytes(hash_message(message),sys.byteorder) >> i & 1] for i in range(256)]
    return signature

def verify(public_key, message, signature):

    signature_hash = [hash_message(signature[i]) for i in range(256)]
    public_key_hash = [public_key[i][int.from_bytes(hash_message(message),sys.byteorder) >> i & 1] for i in range(256)]
    
    return signature_hash == public_key_hash

def run_lamport_signature():
    # Example usage of the Lamport one-time signature scheme
    message = b'I am a byte string'   #byte string

    # Key generation
    private_key, public_key = key_generation()

    # Signing
    signature = sign(private_key, message)
    fake_signature = sign(private_key, b'fake message')

    # Verification
    is_verified = verify(public_key, message, signature)
    fake_verficiation = verify(public_key, message, fake_signature)

    # Output results
    print("====Run Plain Lamport Signature Scheme ====")
    print("Message:", message)
    print("Private Key:", private_key)
    print("Public Key:", public_key)
    print("Signature:", signature)
    print("Verification Result:", is_verified)
    
    print("\nFake Signature:", fake_signature)
    print("Fake Verification Result:", fake_verficiation)

if __name__ == "__main__":
    run_lamport_signature()
