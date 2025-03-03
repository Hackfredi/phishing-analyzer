import imapclient
import os
from dotenv import load_dotenv
from pathlib import Path
import sqlite3

# Load environment variables
dotenv_path = Path(__file__).resolve().parent.parent / "config" / "config.env"
load_dotenv(dotenv_path)

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")

# Database file
DATABASE_FILE = "email_ids.db"

def connect_imap():
    """Connects to IMAP server and returns the connection object."""
    try:
        mail = imapclient.IMAPClient("imap.gmail.com", ssl=True)
        mail.login(EMAIL, PASSWORD)
        mail.select_folder("INBOX")
        print(" IMAP Connection Successful! All steps completed.")
        return mail
    except Exception as e:
        print(f" IMAP Connection Failed: {e}")
        return None

def fetch_x_gm_msgids(mail):
    """Fetches X-GM-MSGID for all emails in the selected folder."""
    try:
        
        email_ids = mail.search()
        print(f" Found {len(email_ids)} emails.")

        x_gm_msgids = mail.fetch(email_ids, ["X-GM-MSGID"])
        print(" X-GM-MSGIDs fetched successfully.")
        return x_gm_msgids
    
    except Exception as e:
        print(f" Failed to fetch X-GM-MSGIDs: {e}")
        return None

def setup_database():
    """Creates a SQLite database and table to store X-GM-MSGIDs."""
    try:
        print(" Setting up database...")
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_ids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                x_gm_msgid TEXT UNIQUE
            )
        ''')
        conn.commit()
        print(" Database setup completed.")
        return conn
    except Exception as e:
        print(f" Database setup failed: {e}")
        return None

def store_x_gm_msgids(conn, x_gm_msgids):
    """Stores X-GM-MSGIDs in the database."""
    try:
        print(" Storing X-GM-MSGIDs in the database...")
        cursor = conn.cursor()
        for email_id, data in x_gm_msgids.items():
            x_gm_msgid = str(data[b"X-GM-MSGID"])
            try:
                cursor.execute("INSERT INTO email_ids (x_gm_msgid) VALUES (?)", (x_gm_msgid,))
            except sqlite3.IntegrityError:
                pass
        conn.commit()
        print(f" Stored {len(x_gm_msgids)} X-GM-MSGIDs in the database.")
    except Exception as e:
        print(f" Failed to store X-GM-MSGIDs: {e}")

def main():
    """Main function to connect to IMAP, fetch X-GM-MSGIDs, and store them in the database."""
    mail = connect_imap()
    if not mail:
        return

    x_gm_msgids = fetch_x_gm_msgids(mail)
    if not x_gm_msgids:
        mail.logout()
        return

    conn = setup_database()
    if not conn:
        mail.logout()
        return

    store_x_gm_msgids(conn, x_gm_msgids)

    conn.close()
    mail.logout()
    print(" All tasks completed successfully.")

if __name__ == "__main__":
    main()