"""
save_token.py
Loads secret value into secret manager
"""
import os
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
CLIENT_SECRETS_FILE = 'C:/Users/Owner/Desktop/Go Phish/Go-Phish/client_secret.json'
flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
creds = flow.run_local_server(port=8080)

with open('token.json', 'w') as token:
    token.write(creds.to_json())

print("token saved")