from dotenv import load_dotenv
load_dotenv()  

import os
from fetch.fetcher import fetch_emails
from content.analyzer import analyze_email

def main():
    print("Starting phishing analyzer...")

    
    emails = fetch_emails()
    print("Emails fetched successfully!")

    
    analysis_results = []
    for email_content in emails:
        result = analyze_email(email_content)
        analysis_results.append(result)
        

if __name__ == "__main__":
    main()
