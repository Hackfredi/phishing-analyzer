import logging
from pathlib import Path
from dotenv import load_dotenv
import os

# Load configuration from config.env
config_path = Path(__file__).resolve().parent.parent / 'config' / 'config.env'
load_dotenv(config_path)

# Configure logging with IMAP username in log format
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO').upper(),
    format=f'%(asctime)s - %(levelname)s - {os.getenv("IMAP_USERNAME", "SYSTEM")} - %(message)s',
    handlers=[
        logging.FileHandler(
            filename=os.getenv('LOG_FILE', 'msgid_processor.log'),
            encoding='utf-8'
        ),
        logging.StreamHandler()
    ]
)

# Example enhanced logger setup
logger = logging.getLogger('email_processor')
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())

# Add error-specific logging if needed
if os.getenv('ENABLE_ERROR_LOGS', 'false').lower() == 'true':
    error_handler = logging.FileHandler('error.log')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(message)s'))
    logger.addHandler(error_handler)

DATABASE_FILE = "email_ids.db"

def connect_database():
    """Create database with proper constraints to prevent duplicates"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS msgids (
                x_gm_msgid TEXT PRIMARY KEY,  -- Primary key ensures uniqueness
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
        conn.commit()
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        raise

def store_msgids(conn, msgids):
    """Bulk insert msgids with duplicate handling"""
    try:
        cursor = conn.cursor()
        # Use INSERT OR IGNORE to silently skip duplicates
        cursor.executemany(
            "INSERT OR IGNORE INTO msgids (x_gm_msgid) VALUES (?)",
            [(msgid,) for msgid in msgids]
        )
        conn.commit()
        new_count = cursor.rowcount
        logging.info(f"Stored {new_count} new msgids (skipped {len(msgids) - new_count} duplicates)")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database insert error: {e}")
        conn.rollback()
        return False

def get_existing_msgids(conn):
    """Retrieve all existing msgids for duplicate checking"""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT x_gm_msgid FROM msgids")
        return {row[0] for row in cursor.fetchall()}
    except sqlite3.Error as e:
        logging.error(f"Database query error: {e}")
        return set()

def fetch_new_msgids(imap_client, existing_msgids):
    """Fetch only new msgids from IMAP server"""
    try:
        imap_client.select_folder('INBOX')  # Changed from select to select_folder
        email_ids = imap_client.search()  # Changed parameter handling
        
        new_msgids = []
        
        for email_id in email_ids:
            try:
                fetch_data = imap_client.fetch(email_id, ['X-GM-MSGID'])
                msgid = fetch_data[email_id][b'X-GM-MSGID'].decode('utf-8').strip()
                
                if msgid and msgid.isdigit() and msgid not in existing_msgids:
                    new_msgids.append(msgid)
                    
            except Exception as e:
                logging.warning(f"Error processing email {email_id}: {e}")
                continue
                
        return new_msgids
    except Exception as e:
        logging.error(f"IMAP error: {e}")
        return []

def main():
    """Main execution with optimized duplicate handling"""
    conn, imap_connector = None, None
    try:
        conn = connect_database()
        imap_connector = IMAPConnector()  # Changed to use the class
        
        # Connect to IMAP server
        success, message = imap_connector.connect()
        if not success:
            raise RuntimeError(f"IMAP connection failed: {message}")
        
        # Get existing msgids once at start
        existing_msgids = get_existing_msgids(conn)
        logging.info(f"Found {len(existing_msgids)} existing msgids in database")
        
        # Fetch only new msgids
        new_msgids = fetch_new_msgids(imap_connector.client, existing_msgids)  # Access client attribute
        logging.info(f"Found {len(new_msgids)} new msgids on server")
        
        if new_msgids:
            store_msgids(conn, new_msgids)
        
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        if imap_connector:
            imap_connector._cleanup()  # Use the cleanup method
        if conn:
            conn.close()
        logging.info("Processing completed")

if __name__ == "__main__":
    main()