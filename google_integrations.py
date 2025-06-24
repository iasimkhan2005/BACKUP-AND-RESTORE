# google_integrations.py
import os
import requests
import base64
import pathlib
from email.message import EmailMessage

from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests
import google.oauth2.credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from dotenv import load_dotenv, find_dotenv


dotenv_path = find_dotenv()
load_dotenv(dotenv_path)

# Retrieve Google Client ID from environment variables
# GOOGLE_CLIENT_ID is used for ID token verification
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

# Determine the path to client_secret.json dynamically
# This assumes client_secret.json is in the same directory as this script.
# If it's in the project root, adjust as needed (e.g., os.path.join(pathlib.Path(__file__).parents[1], 'client_secret.json'))
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, 'client_secret.json')

def get_google_flow(redirect_uri):
    """
    Configures the Google OAuth2.0 flow with necessary scopes.
    The redirect_uri must exactly match what's configured in Google Cloud Console.
    """
    if not os.path.exists(client_secrets_file):
        raise FileNotFoundError(f"client_secret.json not found at: {client_secrets_file}. Please ensure it's in the correct directory.")
    
    # The Flow object automatically reads client_id, client_secret, token_uri from client_secrets.json
    return Flow.from_client_secrets_file(
        client_secrets_file,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/drive.file",
        ],
        redirect_uri=redirect_uri,
    )

def credentials_to_dict(credentials):
    """
    Converts a Google Credentials object to a dictionary for session storage.
    Ensures all necessary fields for refreshing are included.
    """
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token, # Crucial for offline access
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret, # Crucial for refreshing
        'scopes': credentials.scopes,
        'id_token': credentials.id_token # Store for verification if needed later
    }

def get_credentials_from_dict(creds_dict):
    """
    Reconstructs a Google Credentials object from a dictionary,
    explicitly passing necessary fields for refresh functionality.
    """
    if not creds_dict:
        return None
    
    # Extract fields, providing empty strings/None for missing ones to avoid KeyError,
    # though ideally, they should always be present after initial auth.
    token = creds_dict.get('token')
    refresh_token = creds_dict.get('refresh_token')
    token_uri = creds_dict.get('token_uri')
    client_id = creds_dict.get('client_id')
    client_secret = creds_dict.get('client_secret')
    scopes = creds_dict.get('scopes')
    id_token_val = creds_dict.get('id_token') # Renamed to avoid conflict with id_token module

    try:
        # Explicitly pass all parameters needed for the Credentials object,
        # especially those required for the refresh mechanism.
        creds = google.oauth2.credentials.Credentials(
            token=token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            id_token=id_token_val # Pass id_token if available
        )
        return creds
    except Exception as e:
        print(f"ERROR: Failed to reconstruct Google Credentials from dict: {e}")
        # Print the problematic dictionary for debugging purposes (be cautious with sensitive data in logs)
        print(f"DEBUG: Problematic creds_dict content: {creds_dict.keys()}")
        return None

def refresh_credentials_if_needed(creds_dict):
    """
    Refreshes credentials if expired and a refresh token is available.
    Returns the updated dictionary or None if refresh fails.
    """
    creds = get_credentials_from_dict(creds_dict)
    if not creds:
        print("DEBUG: No credentials or failed to reconstruct credentials for refresh.")
        return None # Could not reconstruct credentials

    # Only attempt refresh if expired and a refresh token exists
    if creds.expired and creds.refresh_token:
        try:
            print("DEBUG: Attempting to refresh Google credentials...")
            creds.refresh(google.auth.transport.requests.Request())
            print("DEBUG: Google credentials successfully refreshed.")
            # Return the updated credentials as a dictionary to be stored back in session
            return credentials_to_dict(creds)
        except Exception as e:
            print(f"ERROR: Failed to refresh Google credentials: {e}")
            # This is where the error "The credentials do not contain..." usually occurs.
            # It means even after reconstruction, the `creds` object lacks the fields for refresh.
            return None # Indicate failure to refresh
    
    # If not expired or no refresh token, return the original dict
    # If creds.token is None but not expired, it means the initial token was not granted.
    if creds.token is None and creds.refresh_token:
        print("DEBUG: Access token is None but refresh token exists. Attempting refresh.")
        try:
            creds.refresh(google.auth.transport.requests.Request())
            print("DEBUG: Google credentials successfully refreshed (from None token).")
            return credentials_to_dict(creds)
        except Exception as e:
            print(f"ERROR: Failed to refresh Google credentials from None token: {e}")
            return None

    return creds_dict


def send_email_via_google(credentials_dict, to_email, from_email, subject, body):
    """Sends an email using the Gmail API with the user's session credentials."""
    creds = get_credentials_from_dict(credentials_dict)
    if not creds:
        return False, "Credentials not provided or invalid for email sending."

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = EmailMessage()
        message.set_content(body)
        message['to'] = to_email
        message['from'] = from_email # Should be the authenticated user's email
        message['subject'] = subject

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': encoded_message}

        message = (service.users().messages().send(userId="me", body=create_message).execute())
        print(F'DEBUG: Message Id: {message["id"]}')
        return True, "Email notification sent."
    except Exception as error:
        print(F'ERROR: An error occurred sending email: {error}')
        # Check if the error is due to insufficient scope or invalid credentials
        if "invalid_grant" in str(error) or "unauthorized_client" in str(error):
            return False, "Email notification failed: Authentication error or expired token. Please log in again."
        return False, f"Email notification failed: {error}"


def upload_file_to_drive(credentials_dict, file_path, file_name, user_email, folder_id=None):
    """Uploads a file to Google Drive using the user's session credentials."""
    creds = get_credentials_from_dict(credentials_dict)
    if not creds:
        return False, "Credentials not provided or invalid for Drive upload."

    try:
        service = build('drive', 'v3', credentials=creds)
        file_metadata = {'name': file_name}
        if folder_id:
            file_metadata['parents'] = [folder_id]

        media = MediaFileUpload(file_path, mimetype='application/zip')

        # Find or create "My Backup App" folder in Google Drive
        query = f"name='My Backup App' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        results = service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        items = results.get('files', [])

        backup_app_folder_id = None
        if items:
            backup_app_folder_id = items[0]['id']
            print(f"DEBUG: Found 'My Backup App' folder with ID: {backup_app_folder_id}")
        else:
            print("DEBUG: 'My Backup App' folder not found. Creating it...")
            file_metadata_folder = {
                'name': 'My Backup App',
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder = service.files().create(body=file_metadata_folder, fields='id').execute()
            backup_app_folder_id = folder.get('id')
            print(f"DEBUG: Created 'My Backup App' folder with ID: {backup_app_folder_id}")

        file_metadata['parents'] = [backup_app_folder_id]

        uploaded_file = service.files().create(body=file_metadata, media_body=media, fields='id, webViewLink').execute()
        print(F'DEBUG: File ID: {uploaded_file.get("id")}, View Link: {uploaded_file.get("webViewLink")}')
        return True, f"File uploaded to Google Drive. View: {uploaded_file.get('webViewLink')}"
    except Exception as e:
        print(F'ERROR: An error occurred uploading to Drive: {e}')
        # Check if the error is due to insufficient scope or invalid credentials
        if "invalid_grant" in str(e) or "unauthorized_client" in str(e):
            return False, "Drive upload failed: Authentication error or expired token. Please log in again."
        return False, f"Failed to upload to Google Drive: {e}"

