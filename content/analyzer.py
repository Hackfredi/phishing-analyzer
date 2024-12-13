from datetime import datetime
import re
import socket
import ssl
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("VIRUSTOTAL_API_KEY")
if not api_key:
    exit(1)

blacklist = ['http://phishy.link', 'http://malicious-site.com']
report_lines = []  # Initialize report lines for the final report
phishing_detected = False  # Track if phishing is detected
phishing_reasons = []  # Track reasons for phishing detection

def generate_report(report_content, phishing_detected, phishing_reasons):
    """Generate a report file based on the analysis."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"phishing_report_{timestamp}.txt"
    file_path = os.path.join("reports", filename)
    os.makedirs("reports", exist_ok=True)

    with open(file_path, "w") as report_file:
        report_file.write("\n".join(report_content))
        if phishing_detected:
            report_file.write("\n\nPhishing detected: Yes\n")
            report_file.write("Reasons for phishing detection:\n")
            for reason in phishing_reasons:
                report_file.write(f"- {reason}\n")
        else:
            report_file.write("\n\nPhishing detected: No\n")

    print(f"Report saved to {file_path}")


def analyze_email(content):
    global report_lines, phishing_detected, phishing_reasons
    print("Analyzing email content for phishing indicators...")
    report_lines.append("Analyzing email content for phishing indicators...")

    # Convert content to string if it's not already a string
    if not isinstance(content, str):
        try:
            content = str(content)
        except Exception as e:
            error_message = f"Error: Unable to convert email content to string. Details: {e}"
            print(error_message)
            report_lines.append(error_message)
            return

    try:
        soup = BeautifulSoup(content, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True)]
        print(f"Links found: {links}")
        report_lines.append(f"Links found: {links}")
    except Exception as e:
        error_message = f"Error while parsing email content with BeautifulSoup: {e}"
        print(error_message)
        report_lines.append(error_message)
        return

    for link in links:
        print(f"Checking link: {link}")
        report_lines.append(f"Checking link: {link}")

        # Check if the link is blacklisted
        if is_blacklisted(link, blacklist):
            message = f"Phishing detected: {link} is blacklisted."
            print(message)
            report_lines.append(message)
            phishing_detected = True
            phishing_reasons.append(f"Blacklisted link: {link}")
            continue  # Skip further checks for blacklisted links

        # Keyword Matching (Suspicious Links)
        if is_suspicious_link(link):
            message = f"Potential phishing detected in link: {link}"
            print(message)
            report_lines.append(message)
            phishing_detected = True
            phishing_reasons.append(f"Suspicious link: {link}")

        # VirusTotal API Check
        if check_with_virustotal(link):
            message = f"Phishing detected via VirusTotal: {link}"
            print(message)
            report_lines.append(message)
            phishing_detected = True
            phishing_reasons.append(f"Phishing flagged by VirusTotal: {link}")

        # SSL Certificate Validation
        if is_ssl_invalid(link):
            message = f"Phishing detected: SSL Certificate invalid or missing for {link}"
            print(message)
            report_lines.append(message)
            phishing_detected = True
            phishing_reasons.append(f"Invalid SSL certificate for: {link}")

    analysis_complete_message = "Analysis complete."
    print(analysis_complete_message)
    report_lines.append(analysis_complete_message)

    # Generate the report file after analysis is done
    generate_report(report_lines, phishing_detected, phishing_reasons)


def is_blacklisted(url, blacklist):
    """Check if the URL is in the blacklist."""
    print(f"Checking if {url} is blacklisted.")
    if url in blacklist:
        print(f"{url} is blacklisted.")
        return True
    return False


def is_suspicious_link(url):
    """Check if the URL contains suspicious keywords."""
    suspicious_keywords = ['verify', 'update', 'login', 'secure']
    print(f"Checking for suspicious keywords in {url}.")
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            print(f"Suspicious keyword '{keyword}' found in {url}.")
            return True
    return False


def check_with_virustotal(url):
    """Check if the URL is flagged as phishing using the VirusTotal API."""
    try:
        headers = {"x-apikey": api_key}
        url_id = requests.utils.quote(url, safe='')
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        if response.status_code == 200:
            result = response.json()
            malicious_count = result['data']['attributes']['last_analysis_stats']['malicious']
            print(f"VirusTotal analysis: {malicious_count} malicious detections for {url}")
            report_lines.append(f"VirusTotal analysis: {malicious_count} malicious detections for {url}")
            if malicious_count > 0:
                return True
    except Exception as e:
        print(f"Error while checking VirusTotal: {e}")
        report_lines.append(f"Error while checking VirusTotal: {e}")
    return False


def is_ssl_invalid(url):
    """Check if SSL certificate is invalid for the URL."""
    domain = urlparse(url).hostname
    if domain:
        try:
            # Connect to the domain and check SSL
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                if cert:
                    return False  # SSL is valid
                else:
                    return True  # SSL is missing
        except Exception as e:
            print(f"SSL check failed for {domain}: {e}")
            report_lines.append(f"SSL check failed for {domain}: {e}")
            return True  # SSL is invalid
    return True  # Invalid if no domain


if __name__ == "__main__":
    # Example email content with HTML links
    sample_email_content = """<html><body>Click here to update your bank details: <a href='https://phishy.link'>Update</a></body></html>"""
    
    analyze_email(sample_email_content)
