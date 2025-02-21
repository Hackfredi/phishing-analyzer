import time
import os
from Server.imap_setup import connect_imap  # Correct import path

def get_latest_email(mail):
    """Fetches the latest email in raw format"""
    try:
        mail.select_folder("INBOX")
        email_ids = mail.search(["ALL"])
        if not email_ids:
            print("❌ No emails found.")
            return None

        latest_email_id = email_ids[-1]
        raw_email = mail.fetch([latest_email_id], ["RFC822"])[latest_email_id][b"RFC822"]
        return email.message_from_bytes(raw_email)

    except Exception as e:
        print(f"❌ Error fetching email: {e}")
        return None

def extract_links(email_message):
    """Extracts links from email body"""
    links = set()
    
    for part in email_message.walk():
        if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":
            body = part.get_payload(decode=True).decode(errors="ignore")
            links.update(re.findall(r"https?://[^\s]+", body))  # Extract URLs
    
    return links