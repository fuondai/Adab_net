from cryptography.fernet import Fernet

# Tạo khóa bí mật
secret_key = Fernet.generate_key()

# Lưu khóa bí mật vào file secret.key
with open("../secret.key", "wb") as key_file:
    key_file.write(secret_key)

print("Secret key generated and saved to secret.key.")
