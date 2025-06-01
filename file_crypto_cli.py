import argparse
import getpass
import os
import sys
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib

def generate_key(password: str) -> bytes:
    # Turn password into a 32-byte base64 key for Fernet
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_file(filepath, password, output=None, overwrite=False):
    key = generate_key(password)
    f = Fernet(key)
    with open(filepath, "rb") as file:
        data = file.read()
    encrypted = f.encrypt(data)
    if not output:
        output = filepath + ".enc"
    if os.path.exists(output) and not overwrite:
        print(f"Error: {output} exists. Use --overwrite to overwrite.")
        return
    with open(output, "wb") as file:
        file.write(encrypted)
    print(f"Encrypted: {filepath} -> {output}")

def decrypt_file(filepath, password, output=None, overwrite=False):
    key = generate_key(password)
    f = Fernet(key)
    with open(filepath, "rb") as file:
        data = file.read()
    try:
        decrypted = f.decrypt(data)
    except InvalidToken:
        print(f"Error: Invalid password or corrupted file: {filepath}")
        return
    if not output:
        if filepath.endswith(".enc"):
            output = filepath[:-4]
        else:
            output = filepath + ".dec"
    if os.path.exists(output) and not overwrite:
        print(f"Error: {output} exists. Use --overwrite to overwrite.")
        return
    with open(output, "wb") as file:
        file.write(decrypted)
    print(f"Decrypted: {filepath} -> {output}")

def main():
    parser = argparse.ArgumentParser(description="File Encrypt/Decrypt Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt file(s)")
    enc_parser.add_argument("files", nargs="+", help="File(s) to encrypt")
    enc_parser.add_argument("-o", "--output", help="Output file name (for single file only)")
    enc_parser.add_argument("--overwrite", action="store_true", help="Overwrite output file if exists")

    # Decrypt
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt file(s)")
    dec_parser.add_argument("files", nargs="+", help="File(s) to decrypt")
    dec_parser.add_argument("-o", "--output", help="Output file name (for single file only)")
    dec_parser.add_argument("--overwrite", action="store_true", help="Overwrite output file if exists")

    args = parser.parse_args()

    # Secure password entry
    password = getpass.getpass("Enter password: ")

    if args.command == "encrypt":
        if len(args.files) > 1 and args.output:
            print("Error: --output can only be used with a single input file.")
            sys.exit(1)
        for file in args.files:
            out = args.output if args.output else None
            encrypt_file(file, password, output=out, overwrite=args.overwrite)

    elif args.command == "decrypt":
        if len(args.files) > 1 and args.output:
            print("Error: --output can only be used with a single input file.")
            sys.exit(1)
        for file in args.files:
            out = args.output if args.output else None
            decrypt_file(file, password, output=out, overwrite=args.overwrite)

if __name__ == "__main__":
    main()