import hashlib
import os

def hash_message(message):
    """Here we still use SHA-256 for simplicity. The message length is shorten to 16."""
    """Hashes a message using SHA-256."""
    return hashlib.sha256(message.encode()).hexdigest()

def improved_k_key_generation(k,l):
    """Generates a key pair in k bit for Lamport one-time signature."""
    private_key = [[os.urandom(32) for _ in range(k)] for _ in range(l)]  # Each element is a pair of l-length k-bit strings
    public_key = [[hash_message(private_key[i][j]) for j in range(k)] for i in range(l)]
    return private_key, public_key

def improved_k_sign(private_key, message, k, l):
    """Signs a message in k bit using Lamport one-time signature."""
    if len(message) != l*k:
        raise ValueError("Message length must be l * k bits")

    signature = [private_key[i][int(message[i], 16)] for i in range(l)]
    return signature

def improved_k_verify(public_key, message, signature, l):
    """Verifies a signature using Lamport one-time signature."""
    if len(message) != l*k:
        raise ValueError("Message length must be l * k bits")

    reconstructed_hash = [hash_message(public_key[i][int(message[i], 16)]) for i in range(l)]
    return signature == reconstructed_hash



def run_k_lamport_signature():
    # Example usage of the improved k-Lamport one-time signature scheme
    k = 16
    l = 16
    message = "0123456789ABCDEF"  # 16-k-bit message in hexadecimal
    # Key generation
    private_key, public_key = key_generation(k,l)

    # Signing
    signature = sign(private_key, message, k, l)

    # Verification
    is_verified = verify(public_key, message, signature, l)

    # Output results
    print("Message:", message)
    print("Private Key:", private_key)
    print("Public Key:", public_key)
    print("Signature:", signature)
    print("Verification Result:", is_verified)

if __name__ == "__main__":
    run_k_lamport_signature()
