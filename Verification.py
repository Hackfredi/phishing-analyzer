import sqlite3
import logging
from imapclient import IMAPClient
from email.parser import BytesParser
from dotenv import load_dotenv
import os
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='email_verifier.log'
)

class EmailVerifier:
    def __init__(self, db_file="email_ids.db", phishing_file="phishing_alerts.txt"):
        self.db_file = db_file
        self.phishing_file = phishing_file
        self.imap = None
        load_dotenv(Path(__file__).parent.parent / 'config' / 'config.env')

    def connect_imap(self):
        """Connect to IMAP server"""
        try:
            self.imap = IMAPClient("imap.gmail.com", ssl=True)
            self.imap.login(os.getenv("IMAP_USERNAME"), os.getenv("IMAP_PASSWORD"))
            return True
        except Exception as e:
            logging.error(f"IMAP connection failed: {e}")
            return False

    def fetch_unverified_emails(self):
        """Retrieve unverified emails from database"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS emails (
                        x_gm_msgid TEXT PRIMARY KEY,
                        subject TEXT,
                        verified BOOLEAN DEFAULT 0,
                        is_phishing BOOLEAN DEFAULT 0,
                        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                return conn.execute("""
                    SELECT x_gm_msgid FROM emails 
                    WHERE verified = 0
                """).fetchall()
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return []

    def fetch_email(self, msgid):
        """Fetch email content from IMAP server"""
        try:
            self.imap.select('INBOX')
            data = self.imap.fetch([msgid], ['RFC822', 'BODY[HEADER]'])[msgid]
            
            # Extract subject
            subject = ""
            for line in data[b'BODY[HEADER]'].decode().splitlines():
                if line.lower().startswith('subject:'):
                    subject = line[8:].strip()
                    break
            
            return data[b'RFC822'], subject
        except Exception as e:
            logging.error(f"Error fetching email {msgid}: {e}")
            return None, ""

    def analyze_email(self, raw_email):
        """Analyze email for phishing indicators"""
        try:
            # Add your analysis logic here
            # Return True if phishing, False otherwise
            return False  # Placeholder
        except Exception as e:
            logging.error(f"Analysis error: {e}")
            return False

    def update_database(self, msgid, subject, is_phishing):
        """Update email verification status"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                conn.execute("""
                    UPDATE emails 
                    SET verified = 1,
                        subject = ?,
                        is_phishing = ?
                    WHERE x_gm_msgid = ?
                """, (subject, int(is_phishing), msgid))
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database update error: {e}")

    def log_phishing(self, subject, msgid):
        """Log phishing attempts to file"""
        try:
            with open(self.phishing_file, 'a') as f:
                f.write(f"{msgid} | {subject}\n")
        except Exception as e:
            logging.error(f"Error writing to phishing file: {e}")

    def process_emails(self):
        """Main processing workflow"""
        if not self.connect_imap():
            return False

        try:
            unverified = self.fetch_unverified_emails()
            if not unverified:
                logging.info("No unverified emails found")
                return True

            for (msgid,) in unverified:
                raw_email, subject = self.fetch_email(msgid)
                if not raw_email:
                    continue

                is_phishing = self.analyze_email(raw_email)
                self.update_database(msgid, subject, is_phishing)
                
                if is_phishing:
                    self.log_phishing(subject, msgid)

            return True
        except Exception as e:
            logging.error(f"Processing error: {e}")
            return False
        finally:
            if self.imap:
                self.imap.logout()

if __name__ == "__main__":
    verifier = EmailVerifier()
    if verifier.process_emails():
        print("Email verification completed successfully")
    else:
        print("Email verification failed - check logs")