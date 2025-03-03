import imaplib
import email
from email.header import decode_header
import re
import sqlite3
from imap_setup import connect_imap  # Add this line here

# Database file
DATABASE_FILE = "email_ids.db"

def connect_database():
    try:
        print("Connecting to database...")
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Create table for email attachments if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                x_gm_msgid TEXT,
                filename TEXT,
                content_type TEXT,
                raw_data BLOB,
                UNIQUE(x_gm_msgid, filename)
            )
        ''')

        # Create table for email links if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                x_gm_msgid TEXT,
                link TEXT,
                UNIQUE(x_gm_msgid, link)
            )
        ''')

        conn.commit()
        print(" Database connection established and tables created.")
        return conn
    except Exception as e:
        print(f" Database connection failed: {e}")
        return None

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
        x_gm_msgid = fetch_data[latest_email_id].get(b"X-GM-MSGID", None)

        if not x_gm_msgid:
            mail.delete_messages([latest_email_id])
            print(" Email deleted due to missing X-GM-MSGID.")
            return None, None

        x_gm_msgid = str(x_gm_msgid)
        return email.message_from_bytes(raw_email), x_gm_msgid

    except Exception as e:
        print(f" Error fetching email: {e}")
        return None, None

def extract_attachments(email_message, x_gm_msgid, conn):
    try:
        cursor = conn.cursor()
        for part in email_message.walk():
            if part.get_content_maintype() == "multipart":
                continue  # Skip multipart containers

            filename = part.get_filename()
            if filename:
                content_type = part.get_content_type()
                raw_data = part.get_payload(decode=True)

                
                cursor.execute('''
                    SELECT id FROM email_attachments 
                    WHERE x_gm_msgid = ? AND filename = ?
                ''', (x_gm_msgid, filename))
                existing_attachment = cursor.fetchone()

                if not existing_attachment:
                    
                    cursor.execute('''
                        INSERT INTO email_attachments (x_gm_msgid, filename, content_type, raw_data)
                        VALUES (?, ?, ?, ?)
                    ''', (x_gm_msgid, filename, content_type, raw_data))
                    conn.commit()
                    print(f" Attachment stored: {filename}")
                else:
                    print(f" Attachment already exists: {filename}")

    except Exception as e:
        print(f" Failed to extract attachments: {e}")

def extract_links(email_message, x_gm_msgid, conn):
    try:
        cursor = conn.cursor()
        links = set()
        for part in email_message.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                body = part.get_payload(decode=True).decode(errors="ignore")
                links.update(re.findall(r"https?://[^\s]+", body)) 

        for link in links:
            try:
                cursor.execute('''
                    INSERT INTO email_links (x_gm_msgid, link)
                    VALUES (?, ?)
                ''', (x_gm_msgid, link))
                conn.commit()
                print(f" Link stored:")
            except sqlite3.IntegrityError:

                print(f" Link already exists:")
                continue

    except Exception as e:
        print(f" Failed to extract links: {e}")

def main():
    # Connect to the database
    conn = connect_database()
    if not conn:
        print(" Database connection failed.")
        return

    # Connect to Gmail
    mail = connect_imap()
    if not mail:
        print(" IMAP Connection Failed.")
        return

    # Fetch the latest email and its X-GM-MSGID
    email_msg, x_gm_msgid = get_latest_email(mail)
    if not email_msg or not x_gm_msgid:
        mail.logout()
        return

    # Extract and store attachments
    extract_attachments(email_msg, x_gm_msgid, conn)

    # Extract and store links
    extract_links(email_msg, x_gm_msgid, conn)

    # Close IMAP connection
    mail.logout()
    print(" All tasks completed successfully.")

if __name__ == "__main__":
    main()