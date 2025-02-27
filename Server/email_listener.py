import email
import os
import re
from imap_setup import connect_imap

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

def save_email_data(email_message):
    """Saves email content for analysis"""
    email_dir = "emails/"
    os.makedirs(email_dir, exist_ok=True)
    email_path = os.path.join(email_dir, "latest_email.eml")

    with open(email_path, "w", encoding="utf-8") as f:
        f.write(str(email_message))

    print(f"📩 Email saved for analysis: {email_path}")

if __name__ == "__main__":
    mail = connect_imap()
    if not mail:
        print("❌ IMAP Connection Failed.")
        exit()

    email_msg = get_latest_email(mail)
    if email_msg:
        save_email_data(email_msg)
        links = extract_links(email_msg)

        print("\n🔗 Extracted Links:")
        for link in links:
            print(link)
