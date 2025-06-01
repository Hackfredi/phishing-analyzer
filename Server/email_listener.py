import imaplib
import email
import re
import sqlite3
import logging
from datetime import datetime, timedelta
from email.header import decode_header
from imap_setup import connect_imap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='email_processor.log'
)

# Constants
DATABASE_FILE = "email_ids.db"
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25MB
DB_CLEANUP_DAYS = 30
VALID_MSGID_PATTERN = re.compile(r'^\d+$')  # Gmail's X-GM-MSGID is numeric

def validate_msgid(msgid: str) -> bool:
    """Validate X-GM-MSGID format (Gmail uses numeric IDs)"""
    return bool(VALID_MSGID_PATTERN.match(msgid))

def connect_database():
    """Ensure database tables enforce X-GM-MSGID integrity"""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Tables with STRICT mode (SQLite 3.37+)
        cursor.execute('PRAGMA foreign_keys = ON')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_metadata (
                x_gm_msgid TEXT PRIMARY KEY CHECK(validate_msgid(x_gm_msgid)),
                subject TEXT,
                sender TEXT,
                received_at TIMESTAMP
            ) STRICT
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_attachments (
                id INTEGER PRIMARY KEY,
                x_gm_msgid TEXT REFERENCES email_metadata(x_gm_msgid) ON DELETE CASCADE,
                filename TEXT,
                content_type TEXT,
                raw_data BLOB,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(x_gm_msgid, filename)
            ) STRICT
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_links (
                id INTEGER PRIMARY KEY,
                x_gm_msgid TEXT REFERENCES email_metadata(x_gm_msgid) ON DELETE CASCADE,
                link TEXT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(x_gm_msgid, link)
            ) STRICT
        ''')

        conn.commit()
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database setup failed: {e}")
        if conn:
            conn.close()
        raise

def handle_invalid_email(mail, email_id, reason):
    """Move invalid emails to 'Invalid' folder or delete"""
    try:
        logging.warning(f"Invalid email {email_id}: {reason}")
        mail.create_folder('INVALID')  # Ensure folder exists
        mail.move([email_id], 'INVALID')
        logging.info(f"Moved email {email_id} to INVALID folder")
    except Exception as e:
        logging.error(f"Failed to handle invalid email: {e}")
        mail.delete_messages([email_id])
        logging.warning(f"Deleted email {email_id}")

def process_email(mail, email_id, conn):
    """Robust email processing with X-GM-MSGID validation"""
    try:
        # Fetch critical headers first
        fetch_data = mail.fetch(email_id, ['X-GM-MSGID', 'RFC822.HEADER'])
        msgid = fetch_data[email_id].get(b'X-GM-MSGID')

        # Validate X-GM-MSGID
        if not msgid:
            handle_invalid_email(mail, email_id, "Missing X-GM-MSGID")
            return False

        msgid = msgid.decode()
        if not validate_msgid(msgid):
            handle_invalid_email(mail, email_id, f"Invalid X-GM-MSGID format: {msgid}")
            return False

        # Proceed with processing
        fetch_data = mail.fetch(email_id, ['RFC822'])
        email_msg = email.message_from_bytes(fetch_data[email_id][b'RFC822'])

        # Store metadata
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO email_metadata 
            (x_gm_msgid, subject, sender, received_at)
            VALUES (?, ?, ?, ?)
        ''', (
            msgid,
            str(decode_header(email_msg['Subject'])[0][0]),
            email_msg['From'],
            email_msg['Date']
        ))

        # Process content
        extract_attachments(email_msg, msgid, conn)
        extract_links(email_msg, msgid, conn)
        conn.commit()
        return True

    except Exception as e:
        logging.error(f"Error processing email {email_id}: {e}")
        conn.rollback()
        return False

def main():
    """Main workflow with cascading cleanup"""
    conn, mail = None, None
    try:
        conn = connect_database()
        mail = connect_imap()
        
        if not mail or not conn:
            raise RuntimeError("Initialization failed")

        mail.select('INBOX')
        _, messages = mail.search(None, 'ALL')
        
        for email_id in messages[0].split():
            try:
                process_email(mail, email_id, conn)
            except Exception as e:
                logging.error(f"Failed to process {email_id}: {e}")
                continue

    except KeyboardInterrupt:
        logging.info("Process interrupted by user")
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
    finally:
        if mail:
            mail.close()
            mail.logout()
        if conn:
            conn.close()
        logging.info("Processing completed")

if __name__ == "__main__":
    main()