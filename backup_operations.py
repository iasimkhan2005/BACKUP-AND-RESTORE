import os, shutil, zipfile
from cryptography.fernet import Fernet
import time
import tempfile
from dotenv import load_dotenv, find_dotenv

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        return generate_key()

def zip_directory(folder_path, zip_path):
    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"Source folder not found: {folder_path}")
    shutil.make_archive(zip_path, 'zip', folder_path)

def encrypt_file(zip_path_base, encrypted_path, key): 
    fernet = Fernet(key)
    full_zip_path = zip_path_base + ".zip"

    if not os.path.exists(full_zip_path):
        raise FileNotFoundError(f"Zip file not found: {full_zip_path}")

    with open(full_zip_path, "rb") as file:
        original_data = file.read()
    encrypted_data = fernet.encrypt(original_data)
    with open(encrypted_path, "wb") as enc_file:
        enc_file.write(encrypted_data)
    os.remove(full_zip_path)

def perform_backup_core(folder_path):
    from db import insert_backup_history 
    
    folder_name = os.path.basename(folder_path)
    zip_path_base = f"{tempfile.gettempdir()}/temp_{folder_name}"
    encrypted_backups_dir = os.path.abspath('./encrypted_backups')
    encrypted_path = os.path.join(encrypted_backups_dir, f"{folder_name}_{int(time.time())}.backup")

    os.makedirs(encrypted_backups_dir, exist_ok=True)
    key = load_key()

    try:
        zip_directory(folder_path, zip_path_base)
        encrypt_file(zip_path_base, encrypted_path, key)
        insert_backup_history(folder_name, encrypted_path)
        return True, encrypted_path
    except FileNotFoundError as e:
        return False, f"Backup failed: Source or temporary file not found: {e}"
    except Exception as e:
        if os.path.exists(zip_path_base + ".zip"):
            os.remove(zip_path_base + ".zip")
        return False, f"Backup failed: {e}"