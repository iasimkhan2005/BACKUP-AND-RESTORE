import os, zipfile
from cryptography.fernet import Fernet
from backup_operations import load_key, generate_key 
from google_integrations import send_email_via_google 
# def load_key(): 
#     try:
#         return open("secret.key", "rb").read()
#     except FileNotFoundError:
#         from backup_operations import generate_key
#         return generate_key()

def decrypt_file(encrypted_file_path, decrypted_zip_path, key):
    fernet = Fernet(key)
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")

    with open(encrypted_file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(decrypted_zip_path, "wb") as dec_file:
        dec_file.write(decrypted_data)

def unzip_directory(zip_file_path, extract_path):
    if not os.path.exists(zip_file_path):
        raise FileNotFoundError(f"Zip file not found: {zip_file_path}")
    if not zipfile.is_zipfile(zip_file_path):
        raise zipfile.BadZipFile(f"File is not a valid zip archive: {zip_file_path}")

    os.makedirs(extract_path, exist_ok=True)
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

def perform_restore_core(backup_file_path, restore_location): 
    key = load_key()

    if not os.path.exists(backup_file_path):
        return False, f"Backup file not found at '{backup_file_path}'."

    temp_zip_path = os.path.join(os.path.dirname(backup_file_path), os.path.basename(backup_file_path) + ".temp_decrypted.zip")

    try:
        decrypt_file(backup_file_path, temp_zip_path, key)
        unzip_directory(temp_zip_path, restore_location)
        os.remove(temp_zip_path)
        return True, f"Backup '{os.path.basename(backup_file_path)}' restored successfully to: {restore_location}"
    except FileNotFoundError as e:
        return False, f"Restore failed: {e}"
    except zipfile.BadZipFile as e:
        return False, f"Restore failed: The backup file is corrupted or not a valid zip archive after decryption: {e}"
    except Exception as e:
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)
        return False, f"Restore failed: {e}"