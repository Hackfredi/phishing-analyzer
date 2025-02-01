import imapclient
import os
from dotenv import load_dotenv
from pathlib import Path


dotenv_path = Path(__file__).resolve().parent.parent / "config" / "config.env"
load_dotenv(dotenv_path)

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")

def connect_imap():
    """ Connects to IMAP server and returns the connection object """
    try:
        print("🔄 Attempting to connect to IMAP server...")
        mail = imapclient.IMAPClient("imap.gmail.com", ssl=True)

        mail.login(EMAIL, PASSWORD)

        mail.select_folder("INBOX")

        print("✅ IMAP Connection Successful! All steps completed.")
        return mail
    
    
    except Exception as e:
        print(f"❌ IMAP Connection Failed: {e}")
        return None

if __name__ == "__main__":
    mail = connect_imap()

    if mail:
        print("   ")
    else:
        print("Failed to establish connection.")
