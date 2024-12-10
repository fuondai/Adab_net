import hashlib
import os
import base64
from cryptography.fernet import Fernet
from colorama import Fore, Style

SECRET_KEY_FILE = "secret.key"

def generate_secret_key():
    """Generate and save a secret key with a valid signature."""
    # Generate a new secret key
    secret_key = Fernet.generate_key()

    # Create a random string and encode it with base64
    random_string = "hacker1"  # The predefined string to add complexity
    encoded_random_string = base64.urlsafe_b64encode(random_string.encode()).decode()

    # Generate a salt (random data)
    salt = os.urandom(8)  # Random salt for added complexity

    # Combine secret key, encoded random string, and salt to generate the signature
    signature_input = secret_key + encoded_random_string.encode() + salt
    signature = hashlib.sha256(signature_input).hexdigest()

    # Save the secret key, random string, and signature to the secret.key file
    with open(SECRET_KEY_FILE, "wb") as key_file:
        key_file.write(secret_key)  # Write the secret key
        key_file.write(b"\n")  # Newline separator
        key_file.write(encoded_random_string.encode())  # Write the encoded random string
        key_file.write(b"\n")  # Newline separator
        key_file.write(signature.encode())  # Write the signature

    print(f"{Fore.GREEN}[+] Secret key and signature generated and saved to {SECRET_KEY_FILE}.{Style.RESET_ALL}")

def load_secret_key():
    """Load the secret key from file and verify its validity."""
    if not os.path.isfile(SECRET_KEY_FILE):
        print(f"{Fore.RED}[!] Error: The secret key file '{SECRET_KEY_FILE}' is missing. Please generate it first.{Style.RESET_ALL}")
        return None

    try:
        with open(SECRET_KEY_FILE, "rb") as key_file:
            secret_key = key_file.readline().strip()  # Read the secret key (first line)
            encoded_random_string = key_file.readline().strip()  # Read the random string (second line)
            saved_signature = key_file.readline().strip()  # Read the signature (third line)

        # Decode the random string from base64
        decoded_random_string = base64.urlsafe_b64decode(encoded_random_string).decode()

        # Generate the salt (random data)
        salt = os.urandom(8)  # Generate salt for signature validation

        # Combine the secret key, random string, and salt to recreate the signature
        signature_input = secret_key + encoded_random_string.encode() + salt
        generated_signature = hashlib.sha256(signature_input).hexdigest()

        # Check if the saved signature matches the generated signature
        if saved_signature == generated_signature:
            return secret_key  # If the signature matches, return the valid secret key
        else:
            print(f"{Fore.RED}[!] Error: The secret key is invalid or corrupted.{Style.RESET_ALL}")
            return None

    except Exception as e:
        print(f"{Fore.RED}[!] Error: The secret key file '{SECRET_KEY_FILE}' is invalid. Please regenerate it.{Style.RESET_ALL}")
        return None

def encrypt_api_key(api_key):
    """Encrypt the API key and save it to the LICENSE_FILE."""
    secret_key = load_secret_key()
    if not secret_key:
        print(f"{Fore.RED}[!] Error: Could not load valid secret key. Aborting encryption.{Style.RESET_ALL}")
        return
    cipher = Fernet(secret_key)
    encrypted_key = cipher.encrypt(api_key.encode())
    with open("license.key", "wb") as license_file:
        license_file.write(encrypted_key)

def decrypt_api_key():
    """Decrypt the API key from the LICENSE_FILE."""
    if not os.path.exists("license.key"):
        return None
    secret_key = load_secret_key()
    if not secret_key:
        return None
    cipher = Fernet(secret_key)
    with open("license.key", "rb") as license_file:
        encrypted_key = license_file.read()
    try:
        return cipher.decrypt(encrypted_key).decode()
    except Exception:
        return None
