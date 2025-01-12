# SecureCommunicator

## Introduction
`SecureCommunicator` is a Python-based cryptographic tool designed to demonstrate secure communication practices using RSA encryption and OAEP padding. This tool is intended for educational purposes, particularly useful for students and professionals looking to deepen their understanding of asymmetric encryption and decryption techniques in cybersecurity.

## Features
- **RSA Encryption**: Utilizes RSA, a public-key cryptosystem for secure data transmission.
- **OAEP Padding**: Employs Optimal Asymmetric Encryption Padding (OAEP) for enhanced security and protection against various attacks.
- **Easy-to-use Interface**: Simple methods for encrypting and decrypting messages, allowing users to easily integrate or extend functionalities.

## Requirements
Ensure you have Python installed on your system (Python 3.6 or later recommended). This project depends on the `cryptography` library, which can be installed using pip:

```bash
pip install cryptography

## Installation
Clone this repository to your local machine using:

```bash
Copy code
git clone https://github.com/yourusername/SecureCommunicator.git
cd SecureCommunicator

##Usage
To use SecureCommunicator, instantiate an object of the class and use it to encrypt or decrypt messages. Here is a quick example:

```python
Copy code
from SecureCommunicator import SecureCommunicator

# Initialize the communicator
comms = SecureCommunicator()

# Encrypt a message
encrypted_msg = comms.encrypt_message('Hello World')
print('Encrypted:', encrypted_msg)

# Decrypt the message
decrypted_msg = comms.decrypt_message(encrypted_msg)
print('Decrypted:', decrypted_msg)
How It Works
SecureCommunicator generates a pair of RSA keys during initialization. The public key is used for encrypting messages, while the private key is used for decrypting. OAEP padding is added to the encryption process to ensure security against chosen ciphertext attacks.

##License
This project is licensed under the MIT License - see the LICENSE file for details.
