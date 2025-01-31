import imaplib
import os
from dotenv import load_dotenv

# Load credentials from .env file
dotenv_path = "Credentials/config.env"
load_dotenv(dotenv_path)

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")

# Connect to Gmail IMAP server
mail = imaplib.IMAP4_SSL("imap.gmail.com")
mail.login(EMAIL, PASSWORD)  # Secure login
mail.select("inbox")
