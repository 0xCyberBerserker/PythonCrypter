# File Encryptor

A Python script to encrypt and decrypt files using AES encryption with a password-derived key.

## Features

- Encrypt a text file using an auto-generated password and AES-256-CBC.
- Decrypt the file with a password prompt.
- Uses SHA-512 for key derivation with PBKDF2.

## Requirements

- Python 3.x
- `cryptography` library

### Install Dependencies

To install the required dependencies, use the following command:
```bash
pip install cryptography
```

## Usage

### Encrypt a File

To encrypt a file (`file.txt`), use the following command:

```
python crypter.py -e file.txt
```

This command will output an encrypted file named `file.txt.enc` and display the generated password on the screen.

### Decrypt a File

To decrypt a file (`file.txt.enc`), use:

```bash
python crypter.py -e file.txt
```


- This command generates an encrypted version of `file.txt` named `file.txt.enc`.
- An auto-generated password will be displayed on the screen for decryption purposes.

### Decrypt a File

To decrypt a file (`file.txt.enc`):

```bash
python crypter.py -d file.txt.enc
```

- The program will prompt for the previously generated password.
- Once verified, it will produce a decrypted version of the file named `file_decrypted.txt`.

## License

This project is licensed under the MIT License.