import os
import imaplib
import email
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

def fetch_emails():
    # Check if email credentials are provided
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        raise ValueError("Please set EMAIL_ADDRESS and EMAIL_PASSWORD in the .env file")

    try:
        # Connecting to Gmail's IMAP server
        server = imaplib.IMAP4_SSL('imap.gmail.com')
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.select('inbox')  # Select the inbox folder

        # Search for all emails in the inbox
        status, messages = server.search(None, 'ALL')

        if status != 'OK':
            print("No messages found!")
            return []

        emails = []
        # Loop through all messages and fetch each one
        for num in messages[0].split():
            status, data = server.fetch(num, '(RFC822)')
            if status != 'OK':
                print(f"Failed to fetch message {num}")
                continue

            # Parse the email message
            msg = email.message_from_bytes(data[0][1])
            emails.append(msg)  # Collect emails in the list

        # Logout from the server
        server.close()
        server.logout()

        return emails

    except Exception as e:
        print(f"Error occurred: {e}")
        return []  # Return empty list if an error occurs

def main():
    print("Starting phishing analyzer...")

    # Fetch emails
    emails = fetch_emails()

    if not emails:
        print("No emails fetched.")
        return

    print("Emails fetched successfully!")
    
    # Analyze each email
    for email_content in emails:
        print(f"Subject: {email_content['subject']}")  # Print subject as an example of email analysis

if __name__ == "__main__":
    main()
