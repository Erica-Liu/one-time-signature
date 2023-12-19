# One-time Signature Scheme and Implementation
CO 485 Final project: one time signature

## Introduction
Other than public key cryptography-based digital signature scheme, one-time signature is simply based on one-way functions.
One-time signature scheme was initially developed by Lamport and subsequently enhanced by Merkle and Winternitz.

Simply speaking, the message signer generates a random number $r$ which serves as a one-time private key. Then signer hashes it though an one-way hash function, $h$ to generate the public key $pk = h(r)$. To sign a message $m$, the random private key is used to choose from according to the message $\{0,1\}$ bit, $s = r \oplus m$. When a receiver gets $(m, s)$, if  $h(m \oplus h(r)) = s$, the receiver can verify this signature is from the signer.

A plain implementation is in [plain Lamport one-time signature](one-time-sig.py).

An improved implementation is in [improved k-Lamport one-time signature](improved-one-time-signature.py).

### Key Generation
A one-time signature scheme involves the generation of a public-private key pair. The public key is used for verification, while the private key is used for signing.
Unlike traditional digital signature schemes, the private key in a one-time signature scheme is only valid for a single signature.

### Signing
To sign a message, the user applies a one-time signing algorithm using their private key. This produces a signature that corresponds to the specific message being signed.
Once the signing process is complete, the private key becomes obsolete and should never be used again.

### Verification
The recipient of the message, who knows the public key of the sender, can use the one-time verification algorithm to check the authenticity of the signature.
If the signature is valid, it confirms that the message was indeed signed by the private key corresponding to the public key, and the message has not been altered.

### Security and Use Cases
One-time signatures are often employed in scenarios where the compromise of a signing key poses a significant threat.
Examples of use cases include secure communication in resource-constrained environments, where storing long-term keys securely is challenging.

### Drawbacks
The main drawback of one-time signatures is that, as the name suggests, each key can only be used once. This requires careful management of key pairs to ensure that keys are not reused.
Stateless vs. Stateful Schemes:
Stateless one-time signature schemes generate each key independently of the others. In contrast, stateful schemes generate keys in sequence, relying on the previous key to generate the next one. Stateless schemes may be more resistant to certain attacks, but stateful schemes are often more efficient.
