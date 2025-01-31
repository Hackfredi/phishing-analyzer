import imapclient
import os
from dotenv import load_dotenv

# Load credentials from external .env file
dotenv_path = os.path.join(os.getcwd(), "config", ".env")
load_dotenv(dotenv_path)

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")

def connect_imap():
    """ Connects to IMAP server and returns the connection object """
    try:
        mail = imapclient.IMAPClient("imap.gmail.com", ssl=True)
        mail.login(EMAIL, PASSWORD)
        mail.select_folder("INBOX")
        print("✅ IMAP Connection Successful!")
        return mail
    except Exception as e:
        print(f"❌ IMAP Connection Failed: {e}")
        return None
