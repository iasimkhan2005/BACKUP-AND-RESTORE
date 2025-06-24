import shutil
from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from dotenv import load_dotenv, find_dotenv
import tempfile
import sys # Import sys for platform checks
import pathlib # Used for cleaner path handling

#from Files
from backup_operations import perform_backup_core
from restore_operations import perform_restore_core
from google_integrations import get_google_flow, credentials_to_dict, get_credentials_from_dict, refresh_credentials_if_needed, send_email_via_google, upload_file_to_drive
from db import get_recent_backups
from werkzeug.utils import secure_filename
from usb_operations import get_usb_devices, generate_directory_tree # New imports

#Google imports
from google.oauth2 import id_token
import google.auth.transport.requests
import requests


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Load environment variables
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)

app = Flask(__name__, template_folder='template')
app.secret_key = os.getenv("FLASK_SECRET_KEY", "a_very_secret_key_for_dev")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

ENCRYPTED_BACKUPS_DIR = os.path.abspath('./encrypted_backups')
os.makedirs(ENCRYPTED_BACKUPS_DIR, exist_ok=True)

client_secrets_file = os.path.join(pathlib.Path(__file__).parent, 'client_secret.json')


@app.route("/login")
def login():
    """Initiates the Google OAuth2.0 login process."""
    redirect_uri = url_for("callback", _external=True)
    flow = get_google_flow(redirect_uri)
    authorization_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true")
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    """Handles the callback from Google OAuth2.0."""
    redirect_uri = url_for("callback", _external=True)
    flow = get_google_flow(redirect_uri)

    if "state" not in session or session["state"] != request.args.get("state"):
        flash("Invalid state parameter. Please try logging in again.", "error")
        return redirect(url_for("home_page"))

    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        flash(f"Failed to fetch Google token: {e}", "error")
        return redirect(url_for("home_page"))

    credentials = flow.credentials
    session["credentials"] = credentials_to_dict(credentials)

    request_session = requests.Session()
    token_request = google.auth.transport.requests.Request(session=request_session)

    try:
        id_info = id_token.verify_oauth2_token(
            id_token=credentials.id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10,
        )
    except Exception as e:
        flash(f"Failed to verify Google ID token: {e}", "error")
        session.clear()
        return redirect(url_for("home_page"))

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    flash(f"Logged in as {session['name']}", "success")
    return redirect(url_for("home_page"))

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home_page"))

def get_credentials_from_session_and_refresh():
    creds_dict = session.get('credentials')
    if not creds_dict:
        return None, None
    
    updated_creds_dict = refresh_credentials_if_needed(creds_dict)
    if updated_creds_dict:
        session['credentials'] = updated_creds_dict
        return get_credentials_from_dict(updated_creds_dict), updated_creds_dict
    return None, None


# --- Main Application Routes ---

@app.route('/')
def home_page():
    if 'google_id' in session:
        return render_template("index.html", user=session.get("name"), logged_in=True)
    return render_template("index.html", logged_in=False)

# --- Backup Functionality ---
@app.route('/backup')
def backup_folder_form():
    recent_backups = get_recent_backups()
    return render_template('backup_form.html', backups=recent_backups, logged_in='google_id' in session)


@app.route('/perform_backup', methods=['POST'])
def perform_backup_route():
    # This route handles "Backup a Folder on the Server"
    folder_to_backup = request.form.get('folder_path')
    upload_to_drive_checked = request.form.get('upload_to_drive') == 'on'
    
    # NOTE: The 'save_to_usb' checkbox is NOT in this form currently in backup_form.html
    # If you want USB backup for server path, you need to add the checkbox to this form in HTML.

    if not folder_to_backup:
        flash('Please provide a folder path to backup.', 'error')
        return redirect(url_for('backup_folder_form'))

    if not os.path.isdir(folder_to_backup):
        flash('The provided path is not a valid directory or does not exist on the server.', 'error')
        return redirect(url_for('backup_folder_form'))

    success, backup_file_path = perform_backup_core(folder_to_backup)

    if not success:
        flash(f'Backup failed: {backup_file_path}', 'error')
        return redirect(url_for('backup_folder_form'))

    flash(f'Local backup successful: {os.path.basename(backup_file_path)}', 'success')

    # Google Email Notification
    if 'email' in session:
        creds, creds_dict = get_credentials_from_session_and_refresh()
        if creds and creds_dict:
            email_success, email_message = send_email_via_google(
                creds_dict,
                session['email'],
                session.get('email', 'me'),
                f"Backup Created: {os.path.basename(backup_file_path)}",
                f"Your backup for folder '{os.path.basename(folder_to_backup)}' was successfully created on the server at:\n{backup_file_path}"
            )
            if email_success:
                flash(email_message, 'success')
            else:
                flash(email_message, 'warning')
        else:
            flash("Could not send email: Google credentials unavailable or expired.", "warning")

    # Google Drive Upload
    if upload_to_drive_checked and 'google_id' in session:
        creds, creds_dict = get_credentials_from_session_and_refresh()
        if creds and creds_dict:
            drive_success, drive_message = upload_file_to_drive(
                creds_dict,
                backup_file_path,
                os.path.basename(backup_file_path),
                session['email']
            )
            if drive_success:
                flash(drive_message, 'success')
            else:
                flash(drive_message, 'warning')
        elif upload_to_drive_checked and 'google_id' not in session:
             flash("Google Drive upload requested but you are not logged in with Google.", "warning")

    # No USB functionality here by default.

    return redirect(url_for('backup_folder_form'))


@app.route('/upload_folder_from_client', methods=['POST'])
def upload_folder_from_client():
    # This route handles "Upload a Folder from Your Computer"
    upload_to_drive_checked = request.form.get('upload_to_drive_client') == 'on'
    save_to_usb_checked = request.form.get('save_to_usb') == 'on'
    
    print(f"DEBUG: 'Save to USB' checkbox status for client upload: {save_to_usb_checked}")

    if 'folder_upload' not in request.files:
        flash('No folder selected for upload.', 'error')
        return redirect(url_for('backup_folder_form'))

    files = request.files.getlist('folder_upload')
    if not files or files[0].filename == '':
        flash('No files found in the selected folder.', 'error')
        return redirect(url_for('backup_folder_form'))

    temp_upload_dir_base = None # Temporary base directory for initial upload
    folder_to_backup_for_zip = None # The actual folder that will be zipped
    backup_file_path = None
    try:
        temp_upload_dir_base = tempfile.mkdtemp(prefix="uploaded_client_files_")
        print(f"DEBUG: Created temporary base upload directory: {temp_upload_dir_base}")

        top_level_folder_name = None
        if files:
            # Extract the top-level folder name from the first file's path (e.g., "MyFolder/file.txt" -> "MyFolder")
            top_level_folder_name = pathlib.Path(files[0].filename).parts[0]
            folder_to_backup_for_zip = os.path.join(tempfile.gettempdir(), secure_filename(top_level_folder_name))
            os.makedirs(folder_to_backup_for_zip, exist_ok=True) # Create the target folder

        if not top_level_folder_name: # Fallback if for some reason top_level_folder_name isn't found
            folder_to_backup_for_zip = tempfile.mkdtemp(prefix="uploaded_client_files_flat_")


        for file in files:
            if file.filename:
                # Relative path example: "MyFolder/Subfolder/file.txt"
                relative_path = file.filename
                # Construct the full path within the new target folder
                full_file_path = os.path.join(folder_to_backup_for_zip, relative_path)
                
                # Ensure parent directories exist for the file
                os.makedirs(os.path.dirname(full_file_path), exist_ok=True)
                
                file.save(full_file_path)
                print(f"DEBUG: Saved: {full_file_path}")

        print(f"DEBUG: Files are now prepared in: {folder_to_backup_for_zip}")
        
        success, backup_file_path = perform_backup_core(folder_to_backup_for_zip)

        if not success:
            flash(f'Folder upload and backup failed: {backup_file_path}', 'error')
            return redirect(url_for('backup_folder_form'))

        flash(f'Folder uploaded and local backup successful: {os.path.basename(backup_file_path)}', 'success')

        # Google Email Notification
        if 'email' in session:
            creds, creds_dict = get_credentials_from_session_and_refresh()
            if creds and creds_dict:
                email_success, email_message = send_email_via_google(
                    creds_dict,
                    session['email'],
                    session.get('email', 'me'),
                    f"Backup Created from Upload: {os.path.basename(backup_file_path)}",
                    f"Your uploaded folder was backed up on the server at:\n{backup_file_path}"
                )
                if email_success:
                    flash(email_message, 'success')
                else:
                    flash(email_message, 'warning')
            else:
                flash("Could not send email: Google credentials unavailable or expired.", "warning")

        # Google Drive Upload
        if upload_to_drive_checked and 'google_id' in session:
            creds, creds_dict = get_credentials_from_session_and_refresh()
            if creds and creds_dict:
                drive_success, drive_message = upload_file_to_drive(
                    creds_dict,
                    backup_file_path,
                    os.path.basename(backup_file_path),
                    session['email']
                )
                if drive_success:
                    flash(drive_message, 'success')
                else:
                    flash(drive_message, 'warning')
            else:
                flash("Google Drive upload requested but Google credentials unavailable or expired.", "warning")
        elif upload_to_drive_checked and 'google_id' not in session:
             flash("Google Drive upload requested but you are not logged in with Google.", "warning")

        # --- USB Backup Functionality (NOW CORRECTLY HERE and using selected folder!) ---
        if save_to_usb_checked:
            print("DEBUG: 'Save to USB' checkbox was checked for client upload. Attempting USB detection...")
            usb_drives = get_usb_devices()
            print(f"DEBUG: Detected USB drives: {usb_drives}")

            if usb_drives:
                selected_usb_path = usb_drives[0] # Use the first detected USB drive
                print(f"DEBUG: Selected USB path for directory tree backup: {selected_usb_path}")
                
                # Use the name of the uploaded folder for the directory tree filename
                # If top_level_folder_name is not set (e.g., if files were uploaded without a folder structure),
                # fallback to a generic name or the temp_upload_dir_base name.
                file_tree_name = f"{secure_filename(top_level_folder_name or 'uploaded_folder')}_directory_tree.txt"
                usb_tree_output_path = os.path.join(selected_usb_path, file_tree_name)
                print(f"DEBUG: Full path for directory tree on USB: {usb_tree_output_path}")

                try:
                    # Pass the *actual folder that was backed up* to generate_directory_tree
                    print(f"DEBUG: Calling generate_directory_tree for '{folder_to_backup_for_zip}' to '{usb_tree_output_path}'")
                    generate_directory_tree(folder_to_backup_for_zip, usb_tree_output_path)
                    flash(f"Directory tree saved to USB at: {usb_tree_output_path}", 'success')
                    print("DEBUG: Successfully saved directory tree to USB.")
                except Exception as e:
                    flash(f"Failed to save directory tree to USB: {e}", 'error')
                    print(f"ERROR: Exception while saving directory tree to USB: {e}")
            else:
                flash("No USB drives detected for saving the directory tree.", 'warning')
                print("DEBUG: No USB drives detected.")
        # --- END USB Backup Functionality ---

    except Exception as e:
        flash(f'Error during folder upload and backup: {e}', 'error')
        print(f"ERROR: General exception in upload_folder_from_client: {e}")
    finally:
        # Cleanup both the initial temp_upload_dir_base and the final folder_to_backup_for_zip
        if temp_upload_dir_base and os.path.exists(temp_upload_dir_base):
            shutil.rmtree(temp_upload_dir_base)
            print(f"DEBUG: Cleaned up temporary base upload directory: {temp_upload_dir_base}")
        if folder_to_backup_for_zip and os.path.exists(folder_to_backup_for_zip):
            shutil.rmtree(folder_to_backup_for_zip)
            print(f"DEBUG: Cleaned up final temporary backup directory: {folder_to_backup_for_zip}")


    return redirect(url_for('backup_folder_form'))


# --- Restore Functionality ---
@app.route('/restore')
def restore_form():
    recent_backups = get_recent_backups()
    return render_template('restore_form.html', backups=recent_backups, logged_in='google_id' in session)


@app.route('/perform_restore', methods=['POST'])
def perform_restore_route():
    restore_location = request.form.get('restore_location')
    backup_file_source = request.form.get('backup_source_type')

    if not restore_location:
        flash('Please provide a restore location.', 'error')
        return redirect(url_for('restore_form'))

    if not os.path.isdir(restore_location):
        try:
            os.makedirs(restore_location, exist_ok=True)
            flash(f"Restore location '{restore_location}' created.", 'info')
        except OSError as e:
            flash(f'Invalid restore location or permission denied: {e}', 'error')
            return redirect(url_for('restore_form'))

    backup_file_path_to_use = None
    temp_uploaded_backup_file = None

    if backup_file_source == 'history':
        backup_file_path_to_use = request.form.get('backup_file_path')
        if not backup_file_path_to_use:
            flash('No backup file selected from history.', 'error')
            return redirect(url_for('restore_form'))

        absolute_backup_file_path = os.path.abspath(backup_file_path_to_use)

        print(f"DEBUG: Path from history: '{backup_file_path_to_use}'")
        print(f"DEBUG: Absolute backup path: '{absolute_backup_file_path}'")
        print(f"DEBUG: Base encrypted directory: '{ENCRYPTED_BACKUPS_DIR}'")
        print(f"DEBUG: Does absolute path exist? {os.path.exists(absolute_backup_file_path)}")
        print(f"DEBUG: Is absolute path within authorized dir? {absolute_backup_file_path.startswith(ENCRYPTED_BACKUPS_DIR)}")

        if not os.path.exists(absolute_backup_file_path) or not absolute_backup_file_path.startswith(ENCRYPTED_BACKUPS_DIR):
            flash('Invalid or unauthorized backup file path selected. Please ensure the file exists and is in the designated backup directory.', 'error')
            return redirect(url_for('restore_form'))

        backup_file_path_to_use = absolute_backup_file_path

    elif backup_file_source == 'upload':
        if 'uploaded_backup_file' not in request.files:
            flash('No backup file uploaded.', 'error')
            return redirect(url_for('restore_form'))

        uploaded_file = request.files['uploaded_backup_file']
        if uploaded_file.filename == '':
            flash('No selected file for upload.', 'error')
            return redirect(url_for('restore_form'))

        if uploaded_file and uploaded_file.filename.endswith('.backup'):
            filename = secure_filename(uploaded_file.filename)
            temp_uploaded_backup_file = os.path.join(tempfile.gettempdir(), filename)
            uploaded_file.save(temp_uploaded_backup_file)
            backup_file_path_to_use = temp_uploaded_backup_file
        else:
            flash('Invalid file type. Please upload a .backup file.', 'error')
            return redirect(url_for('restore_form'))
    else:
        flash('Invalid backup source selected.', 'error')
        return redirect(url_for('restore_form'))

    success, message = perform_restore_core(backup_file_path_to_use, restore_location)

    if temp_uploaded_backup_file and os.path.exists(temp_uploaded_backup_file):
        os.remove(temp_uploaded_backup_file)
        print(f"DEBUG: Cleaned up temporary uploaded backup file: {temp_uploaded_backup_file}")

    if success:
        flash(f'Restore successful: {message}', 'success')
        if 'email' in session:
            creds, creds_dict = get_credentials_from_session_and_refresh()
            if creds and creds_dict:
                email_success, email_message = send_email_via_google(
                    creds_dict,
                    session['email'],
                    session.get('email', 'me'),
                    f"Backup Restored: {os.path.basename(backup_file_path_to_use)}",
                    f"Your backup '{os.path.basename(backup_file_path_to_use)}' was successfully restored to:\n{restore_location}"
                )
                if email_success:
                    flash(email_message, 'success')
                else:
                    flash(email_message, 'warning')
            else:
                flash("Could not send email: Google credentials unavailable or expired.", "warning")
    else:
        flash(f'Restore failed: {message}', 'error')

    return redirect(url_for('restore_form'))


@app.route('/usb_trigger')
def usb_trigger_placeholder():
    flash('USB Trigger functionality is now integrated into the backup process.', 'info')
    return render_template('usb_trigger_placeholder.html')

if __name__ == '__main__':
    app.run(debug=True)

