import email
import os
import re
import sqlite3
from imap_setup import connect_imap

# Database file
DATABASE_FILE = "email_ids.db"

def connect_database():
    try:
        print("Connecting to database...")
        conn = sqlite3.connect(DATABASE_FILE)
        print(" Database connection established.")
        return conn
    except Exception as e:
        print(f" Database connection failed: {e}")
        return None

def update_x_gm_msgid(conn, x_gm_msgid):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT x_gm_msgid FROM email_ids WHERE x_gm_msgid = ?", (x_gm_msgid,))
        if cursor.fetchone():
            print(f" X-GM-MSGID already exists: {x_gm_msgid}")
        else:
            cursor.execute("INSERT INTO email_ids (x_gm_msgid) VALUES (?)", (x_gm_msgid,))
            conn.commit()
            print(f" New X-GM-MSGID stored: {x_gm_msgid}")
    except Exception as e:
        print(f" Failed to update X-GM-MSGID: {e}")

def get_latest_email(mail):
    try:
        mail.select_folder("INBOX")
        email_ids = mail.search(["ALL"])
        if not email_ids:
            print(" No emails found.")
            return None, None

        latest_email_id = email_ids[-1]
        fetch_data = mail.fetch([latest_email_id], ["RFC822", "X-GM-MSGID"])
        raw_email = fetch_data[latest_email_id][b"RFC822"]
        x_gm_msgid = str(fetch_data[latest_email_id][b"X-GM-MSGID"])
        return email.message_from_bytes(raw_email), x_gm_msgid

    except Exception as e:
        print(f" Error fetching email: {e}")
        return None, None

def extract_links(email_message):
    links = set()
    for part in email_message.walk():
        if part.get_content_type() in ["text/plain", "text/html"]:
            body = part.get_payload(decode=True).decode(errors="ignore")
            links.update(re.findall(r"https?://[^\s]+", body))  # Extract URLs
    return links

def save_email_data(email_message):
    email_dir = "emails/"
    os.makedirs(email_dir, exist_ok=True)
    email_path = os.path.join(email_dir, "latest_email.eml")

    with open(email_path, "w", encoding="utf-8") as f:
        f.write(str(email_message))

    print(f" Email saved for analysis: {email_path}")

def main():
    """Main function to check for new X-GM-MSGID and update the database."""
    # Connect to the database
    conn = connect_database()
    if not conn:
        print(" Database connection failed.")
        return

    # Connect to Gmail
    mail = connect_imap()
    if not mail:
        print(" IMAP Connection Failed.")
        conn.close()
        return

    # Fetch the latest email and its X-GM-MSGID
    email_msg, x_gm_msgid = get_latest_email(mail)
    if not email_msg or not x_gm_msgid:
        mail.logout()
        conn.close()
        return

    # Update the X-GM-MSGID in the database
    update_x_gm_msgid(conn, x_gm_msgid)

    # Save the email content for analysis
    save_email_data(email_msg)

    # Extract
    links = extract_links(email_msg)

    # Close connections
    mail.logout()
    conn.close()
    print(" All tasks completed successfully.")

if __name__ == "__main__":
    main()
