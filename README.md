# One-time Signature Scheme and Implementation
CO 485 Final project: one time signature

## Introduction
Other than public key cryptography-based digital signature scheme, one-time signature is simply based on one-way functions.
One-time signature scheme was initially developed by Lamport and subsequently enhanced by Merkle and Winternitz.

Simply speaking, the message signer generates a random number $r$ which serves as a one-time private key. Then signer hashes it though an one-way hash function, $h$ to generate the public key $pk = h(r)$. To sign a message $m$, the random private key is used to choose from according to the message $\{0,1\}$ bit, $s = r \xor m$. When a receiver gets $(m, s)$, if  $h(m \xor h(r)) = s$, the receiver can verify this signature is from the signer.

