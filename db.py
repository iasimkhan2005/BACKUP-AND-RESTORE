import mysql.connector
import os
from dotenv import find_dotenv,load_dotenv
#get the env file and load it
dotenv_path =  find_dotenv()
load_dotenv(dotenv_path)

def connect_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB")
    )

def insert_backup_history(folder_name, backup_path):
    conn = connect_db()
    cursor = conn.cursor()
    query = "INSERT INTO backup_history (folder_name, backup_file_path) VALUES (%s, %s)"
    cursor.execute(query, (folder_name, backup_path))
    conn.commit()
    cursor.close()
    conn.close()

def get_recent_backups(limit=10):
    conn = connect_db()
    cursor = conn.cursor()
    query = "SELECT id, folder_name, backup_file_path, timestamp FROM backup_history ORDER BY timestamp DESC LIMIT %s"
    cursor.execute(query, (limit,))
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results
