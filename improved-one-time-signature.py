import hashlib
import os
import sys
import math

def hash_message(message):
    """Hashes a message using SHA-256."""
    return hashlib.sha256(message).digest()

def improved_k_key_generation(k,l):
    """Generates a key pair in k bit for Lamport one-time signature."""
    byte_num = int(l / 8)
    private_key = [[os.urandom(32) for _ in range(k)] for _ in range(l)]  # Each element is a pair of l-length k-bit strings
    public_key = [[hash_message(private_key[i][j]) for j in range(k)] for i in range(l)]
    return private_key, public_key
    
def finding_logk_bit_idx(m, k, l):
    bit_group_num = int (math.log2(k))
    logk_bits = [0 for _ in range(l)]
    for i in range(l):
      idx = 0
      for j in range(bit_group_num):
        #print("i,j:", i, j)
        bit_pos = i * bit_group_num + j
        this_bit = int.from_bytes(hash_message(m),sys.byteorder) >> bit_pos & 1
        #print("bit pos #", bit_pos, ": ", this_bit)
        idx += this_bit * (2**j)
        #print("idx number:", idx)
      logk_bits[i] = idx
    return logk_bits

def improved_k_sign(private_key, message, k, l):
  # finding the logk-bit index number after hashing
    indices = finding_logk_bit_idx(message, k, l)

    signature = [private_key[i][indices[i]] for i in range(l)]
    return signature

def improved_k_verify(public_key, message, signature, k, l):
   
    signature_hash = [hash_message(signature[i]) for i in range(l)]
   
    indices = finding_logk_bit_idx(message, k, l)

    public_key_hash = [public_key[i][indices[i]] for i in range(l)]
    
    return signature_hash == public_key_hash


def run_k_lamport_signature():
    # Example usage of the improved k-Lamport one-time signature scheme
    k = 16
    l = 16
    message = b'I am a byte string'  # 16-k-bit message in hexadecimal
    # Key generation
    private_key, public_key = improved_k_key_generation(k,l)

    # Signing
    signature = improved_k_sign(private_key, message, k, l)
    fake_signature = improved_k_sign(private_key, b'fake message', k, l)

    # Verification
    is_verified = improved_k_verify(public_key, message, signature, k, l)

    # Fake Verification
    fake_verficiation = improved_k_verify(public_key, message, fake_signature, k, l)

    # Output results
    print("Message:", message)
    print("Private Key:", private_key)
    print("Public Key:", public_key)
    print("Signature:", signature)
    print("Verification Result:", is_verified)
    print("Fake Verification Result:", fake_verficiation)

if __name__ == "__main__":
    run_k_lamport_signature()
