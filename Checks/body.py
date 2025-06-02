import os
from dotenv import load_dotenv
import re
import requests
import whois
from datetime import datetime
import tldextract
from urllib.parse import urlparse
from pathlib import Path

# Load environment variables from the specified .env file
env_path = Path('config') / 'config1.env'
load_dotenv(dotenv_path=env_path)

# Access VirusTotal API key from environment variable
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY not set in config1.env")

def scan_email_body(body: str) -> int:
    """
    Scan email body for phishing indicators
    Returns:
        1 if phishing (count > 5)
        0 if legitimate
    """
    count = 0
    urls = extract_urls(body)
    
    if not urls:
        return 0  # No URLs to check
    
    for url in urls:
        # Rule a: Blacklisted domain
        if check_blacklisted(url):
            count += 1
        
        # Rule b: Domain age
        if check_domain_age(url) < 365:  # Less than 1 year
            count += 1
        
        # Rule c: WHOIS privacy
        if check_whois_privacy(url):
            count += 1
        
        # Rule e: Suspicious TLDs
        if check_suspicious_tld(url):
            count += 1
        
        # Rule f: IP address in URL
        if check_ip_url(url):
            count += 1
        
        # Rule g: Subdomain abuse
        if check_subdomain_abuse(url):
            count += 1
        
        # Rule h: URL length
        if len(url) > 100:  # Arbitrary threshold
            count += 1
        
        # Rule k: HTTPS usage
        if not url.startswith('https://'):
            count += 1
        
        # Rule m: Phishing keywords
        if check_phishing_keywords(url):
            count += 1
        
        # Rule n: Brand impersonation
        if check_brand_impersonation(url):
            count += 1
        
        # Rule o: Unusual paths
        if check_unusual_paths(url):
            count += 1
    
    # Rule q: Frequency of URLs
    if len(urls) > 3:  # More than 3 URLs
        count += 1
    
    # Rule r: VirusTotal check (for the first URL)
    if urls and check_virustotal(urls[0]):
        count += 1
    
    return 1 if count > 5 else 0

# Helper functions
def extract_urls(text: str) -> list:
    """Extract all URLs from text"""
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .\-?=&%#+]*'
    return re.findall(url_pattern, text)

def check_blacklisted(url: str) -> bool:
    """Check if domain is blacklisted (simplified)"""
    domain = urlparse(url).netloc
    # In production, use Google Safe Browsing API or similar
    return False  # Placeholder

def check_domain_age(url: str) -> int:
    """Get domain age in days"""
    domain = tldextract.extract(url).registered_domain
    try:
        whois_info = whois.whois(domain)
        if whois_info.creation_date:
            if isinstance(whois_info.creation_date, list):
                creation_date = whois_info.creation_date[0]
            else:
                creation_date = whois_info.creation_date
            return (datetime.now() - creation_date).days
    except:
        pass
    return 0  # Default to risky if we can't check

def check_whois_privacy(url: str) -> bool:
    """Check if WHOIS info is private"""
    domain = tldextract.extract(url).registered_domain
    try:
        whois_info = whois.whois(domain)
        return "PRIVACY" in str(whois_info).upper()
    except:
        return False

def check_suspicious_tld(url: str) -> bool:
    """Check for suspicious top-level domains"""
    suspicious_tlds = {'.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.ga', '.buzz'}
    ext = tldextract.extract(url)
    return f".{ext.suffix}" in suspicious_tlds

def check_ip_url(url: str) -> bool:
    """Check if URL contains raw IP address"""
    domain = urlparse(url).netloc
    return bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))

def check_subdomain_abuse(url: str) -> bool:
    """Check for suspicious subdomain usage"""
    ext = tldextract.extract(url)
    # Check if subdomain contains brand names
    brands = {'paypal', 'amazon', 'ebay', 'bank', 'security', 'login'}
    return any(brand in ext.subdomain.lower() for brand in brands)

def check_phishing_keywords(url: str) -> bool:
    """Check for phishing keywords in URL"""
    keywords = {
        'verify', 'login', 'secure', 'account', 'update', 'confirm',
        'urgent', 'suspended', 'limited', 'action', 'required'
    }
    return any(keyword in url.lower() for keyword in keywords)

def check_brand_impersonation(url: str) -> bool:
    """Check for brand impersonation in domain"""
    ext = tldextract.extract(url)
    domain = ext.domain + '.' + ext.suffix
    # Common brand misspellings
    misspellings = {
        'paypal': ['paypall', 'payypal', 'paipal'],
        'amazon': ['amaz0n', 'amazoon', 'amazn'],
        'ebay': ['eebay', 'ebbay', 'eebay']
    }
    for brand, variants in misspellings.items():
        if brand in domain.lower():
            return False  # Exact match is good
        if any(v in domain.lower() for v in variants):
            return True
    return False

def check_unusual_paths(url: str) -> bool:
    """Check for unusual URL paths"""
    suspicious_paths = {
        '/login.php', '/verify', '/secure', '/account',
        '/admin', '/wp-admin', '/wp-login'
    }
    path = urlparse(url).path.lower()
    return any(p in path for p in suspicious_paths)

def check_virustotal(url: str) -> bool:
    """Check URL with VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        return False
        
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    try:
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/url/report',
            params=params,
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            return result.get('positives', 0) > 0  # If any engines flagged it
    except:
        pass
    return False

# Example usage
if __name__ == "__main__":
    email_body = """
    Dear customer, your account has been limited. Please verify your details immediately:
    https://amaz0n-security.com/login.php?user=admin
    Click here: http://192.168.1.1/secure-update
    """
    
    result = scan_email_body(email_body)
    print(f"Phishing detection result: {result} (1 = phishing, 0 = legitimate)")