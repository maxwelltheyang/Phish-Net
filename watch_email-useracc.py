"""
watch_email-useracc.py
Sets up a watch for the pub/sub to trigger the cloud function when there is a new email in my inbox
"""

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import os
from dotenv import load_dotenv

load_dotenv()
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

client_config = {
    "installed": {
        "client_id": "12836418632-3mg5et1et5spbvhnna2cpdbmscpha82q.apps.googleusercontent.com",
        "project_id": "mystic-span-415322",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": CLIENT_SECRET,
        "redirect_uris": ["http://localhost:8080/"]
    }
}

SCOPES = ['https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/pubsub', 'https://www.googleapis.com/auth/cloud-platform']

def setup_watch():
    """
    Creates a watch to trigger the pub/sub on arrival of new email
    Params: none
    Returns: none
    """
    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
    credentials = flow.run_local_server(port=8080)
    service = build('gmail', 'v1', credentials=credentials)
    request = {
        'labelIds': ['INBOX'],
        'topicName': 'projects/mystic-span-415322/topics/email-push'
    }
    service.users().watch(userId='me', body=request).execute()

setup_watch()
