import sqlite3
import logging
from imapclient import IMAPClient
from email.parser import BytesParser
from typing import Dict, List, Tuple
from pathlib import Path
from dotenv import load_dotenv
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='email_analyzer.log'
)

# Import analysis functions from check folder
from Checks.header import header
from Checks.body import scan_email_body

class EmailVerifier:
    def __init__(self, db_file: str = "email_ids.db", phishing_file: str = "phishing_alerts.txt"):
        self.db_file = db_file
        self.phishing_file = phishing_file
        self.imap = None
        
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
    
    def fetch_unverified_msgids(self) -> List[str]:
        """Retrieve unverified X-GM-MSGIDs from database"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT x_gm_msgid FROM msgids 
                    WHERE verified = 0 OR verified IS NULL
                    ORDER BY processed_at DESC
                    LIMIT 100  # Process batches of 100
                """)
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return []
    
    def fetch_email_data(self, msgid: str) -> Tuple[bytes, str]:
        """Fetch raw email and subject from IMAP server"""
        try:
            self.imap.select('INBOX')
            data = self.imap.fetch([msgid], ['RFC822', 'BODY.PEEK[HEADER]'])[msgid]
            
            # Get subject from headers
            headers = data[b'BODY[HEADER]'].decode('utf-8')
            subject = ""
            for line in headers.splitlines():
                if line.lower().startswith('subject:'):
                    subject = line[8:].strip()
                    break
            
            return data[b'RFC822'], subject
        except Exception as e:
            logging.error(f"Error fetching email {msgid}: {e}")
            return None, ""

    def analyze_email(self, raw_email: bytes) -> Dict[str, int]:
        """Run both header and body analysis on raw email"""
        try:
            email_msg = BytesParser().parsebytes(raw_email)
            
            # Header analysis
            headers_str = "\n".join(f"{k}: {v}" for k, v in email_msg.items())
            header_result = header(headers_str)
            
            # Body analysis
            body = ""
            if email_msg.is_multipart():
                for part in email_msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
            else:
                body = email_msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            body_result = scan_email_body(body)
            
            return {
                "header_verdict": header_result,
                "body_verdict": body_result,
                "is_phishing": 1 if (header_result == 1 or body_result == 1) else 0
            }
        except Exception as e:
            logging.error(f"Analysis error: {e}")
            return {"is_phishing": 0}

    def update_database(self, msgid: str, is_phishing: int, subject: str = ""):
        """Update database with verification status"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                # Add verified column if not exists
                cursor.execute("""
                    ALTER TABLE msgids 
                    ADD COLUMN IF NOT EXISTS verified INTEGER DEFAULT 0
                """)
                
                # Add phishing column if not exists
                cursor.execute("""
                    ALTER TABLE msgids 
                    ADD COLUMN IF NOT EXISTS phishing INTEGER DEFAULT 0
                """)
                
                # Add subject column if not exists
                cursor.execute("""
                    ALTER TABLE msgids 
                    ADD COLUMN IF NOT EXISTS subject TEXT DEFAULT ''
                """)
                
                # Update the record
                cursor.execute("""
                    UPDATE msgids 
                    SET verified = 1,
                        phishing = ?,
                        subject = ?
                    WHERE x_gm_msgid = ?
                """, (is_phishing, subject, msgid))
                
                conn.commit()
                logging.info(f"Updated database for {msgid}")
        except sqlite3.Error as e:
            logging.error(f"Database update error: {e}")

    def log_phishing_attempt(self, subject: str, msgid: str):
        """Write phishing alert to text file"""
        try:
            with open(self.phishing_file, 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {msgid} - {subject}\n")
            logging.info(f"Logged phishing attempt: {subject}")
        except Exception as e:
            logging.error(f"Error writing to phishing file: {e}")

    def process_emails(self):
        """Main processing workflow"""
        if not self.connect_imap():
            return False
        
        msgids = self.fetch_unverified_msgids()
        if not msgids:
            logging.info("No unverified emails found")
            return True
        
        logging.info(f"Found {len(msgids)} unverified emails")
        
        for msgid in msgids:
            raw_email, subject = self.fetch_email_data(msgid)
            if not raw_email:
                continue
            
            analysis = self.analyze_email(raw_email)
            if not analysis:
                continue
            
            is_phishing = analysis.get('is_phishing', 0)
            self.update_database(msgid, is_phishing, subject)
            
            if is_phishing:
                self.log_phishing_attempt(subject, msgid)
        
        self.imap.logout()
        return True

if __name__ == "__main__":
    verifier = EmailVerifier()
    if verifier.process_emails():
        print("Email verification completed successfully")
    else:
        print("Email verification failed - check logs")