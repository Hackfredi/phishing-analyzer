import imapclient
import ssl
import time
import logging
from typing import Optional, Tuple
from pathlib import Path
from dotenv import load_dotenv
import os

class IMAPConnector:
    def __init__(self, config_path: str = None):
        """
        Initialize IMAP connector with optional config path
        Args:
            config_path: Path to .env config file (default looks in parent/config/config.env)
        """
        self.client: Optional[imapclient.IMAPClient] = None
        self.logger = logging.getLogger('IMAPConnector')
        self.config_path = config_path or str(Path(__file__).parent.parent / 'config' / 'config.env')
        self._load_config()

    def _load_config(self) -> bool:
        """Load configuration from .env file"""
        try:
            load_dotenv(self.config_path)
            self.host = os.getenv("IMAP_HOST", "imap.gmail.com")
            self.port = int(os.getenv("IMAP_PORT", "993"))
            self.username = os.getenv("IMAP_USERNAME")
            self.password = os.getenv("IMAP_PASSWORD")
            self.timeout = int(os.getenv("IMAP_TIMEOUT", "30"))
            
            if not all([self.username, self.password]):
                self.logger.error("Missing required credentials in config")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Config loading failed: {str(e)}")
            return False

    def connect(self, max_retries: int = 3, retry_delay: int = 5) -> Tuple[bool, str]:
        """Establish IMAP connection using config values"""
        if not self._load_config():
            return False, "Config loading failed"

        for attempt in range(max_retries):
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED

                self.client = imapclient.IMAPClient(
                    host=self.host,
                    port=self.port,
                    ssl_context=ssl_context,
                    timeout=self.timeout
                )

                self.client.login(self.username, self.password)
                self.logger.info(f"Connected to {self.host}:{self.port}")
                return True, "Connection successful"

            except ssl.SSLError as e:
                error_msg = f"SSL error (attempt {attempt+1}): {str(e)}"
                if "certificate verify failed" in str(e):
                    error_msg += "\nTip: Check system time/date or add certificate"
            except imapclient.exceptions.LoginError:
                error_msg = "Login failed - check credentials"
                break  # No point retrying with bad credentials
            except Exception as e:
                error_msg = f"Connection error (attempt {attempt+1}): {str(e)}"

            self._cleanup()
            if attempt < max_retries - 1:
                time.sleep(retry_delay)

        self.logger.error(error_msg)
        return False, error_msg

    def _cleanup(self):
        """Clean up connection resources"""
        if self.client:
            try:
                if self.client.is_connected():
                    self.client.logout()
            except Exception as e:
                self.logger.warning(f"Error during cleanup: {str(e)}")
            finally:
                self.client = None

    def __enter__(self):
        success, message = self.connect()
        if not success:
            raise ConnectionError(message)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Using default config path (parent/config/config.env)
    with IMAPConnector() as connector:
        print("Connection successful!")
        print("Server capabilities:", connector.client.capabilities())
        
        # Example: Count inbox messages
        connector.client.select_folder('INBOX')
        messages = connector.client.search()
        print(f"Found {len(messages)} messages in INBOX")