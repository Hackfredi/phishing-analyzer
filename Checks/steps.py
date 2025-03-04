import tldextract
import re

# Method to check if a raw IP address is present in the URL
def check_raw_ip(url):
    # Regular expression to match IPv4 and IPv6 addresses
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    
    # Extract the domain from the URL
    extracted = tldextract.extract(url)
    domain = extracted.domain
    
    # Check for IPv4 or IPv6 addresses
    if re.search(ipv4_pattern, domain) or re.search(ipv6_pattern, domain):
        print(f"Raw IP detected in URL: {url} (+10)")
        return 10  # Add 10 to the total score
    else:
        print(f"No raw IP detected in URL: {url} (+0)")
        return 0

# Method to check for excessive subdomains
def check_excessive_subdomains(url):
    # Extract the domain from the URL
    extracted = tldextract.extract(url)
    subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
    
    # Count the number of subdomains
    num_subdomains = len(subdomains)
    
    # Assign scores based on the number of subdomains
    if num_subdomains >= 4:
        print(f"Excessive subdomains detected: {num_subdomains} (+10)")
        return 10
    elif num_subdomains == 3:
        print(f"Excessive subdomains detected: {num_subdomains} (+5)")
        return 5
    else:
        print(f"No excessive subdomains detected: {num_subdomains} (+0)")
        return 0

# Method to check for lack of HTTPS
def check_lack_of_https(url):
    if not url.startswith("https://"):
        print(f"No HTTPS detected: {url} (+10)")
        return 10
    else:
        print(f"HTTPS detected: {url} (+0)")
        return 0

# Method to check for long URL length
def check_long_url_length(url):
    if len(url) > 75:
        print(f"Long URL detected: {len(url)} characters (+10)")
        return 10
    elif len(url) > 50:
        print(f"Moderately long URL detected: {len(url)} characters (+5)")
        return 5
    else:
        print(f"URL length is within limits: {len(url)} characters (+0)")
        return 0

# Method to check for URL encoding or obfuscation
def check_url_encoding(url):
    score = 0
    
    # Check for encoded parameters (e.g., %20, %3D)
    encoded_pattern = r'%[0-9a-fA-F]{2}'
    if re.search(encoded_pattern, url):
        print(f"URL encoding detected: {url} (+5)")
        score += 5
    
    # Check for heavy obfuscation (e.g., @, //)
    obfuscation_pattern = r'[@\/\/]'
    if re.search(obfuscation_pattern, url):
        print(f"URL obfuscation detected: {url} (+10)")
        score += 10
    
    return score

# Method to check for unusual TLDs
def check_unusual_tlds(url):
    # Extract the TLD
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    
    # List of unusual or suspicious TLDs
    unusual_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".biz"]
    
    if tld in unusual_tlds:
        print(f"Unusual TLD detected: {tld} (+10)")
        return 10
    elif tld not in [".com", ".org", ".net", ".edu", ".gov"]:
        print(f"Less common TLD detected: {tld} (+5)")
        return 5
    else:
        print(f"Common TLD detected: {tld} (+0)")
        return 0

# Method to check for suspicious characters
def check_suspicious_characters(url):
    # List of suspicious characters
    suspicious_chars = ["@", "//", "-", "_"]
    
    # Count occurrences of suspicious characters
    score = 0
    for char in suspicious_chars:
        count = url.count(char)
        if count > 0:
            print(f"Suspicious character '{char}' detected: {count} times (+{min(count, 2) * 5})")
            score += min(count, 2) * 5  # Max of 10 points
    
    return score

# Method to evaluate the URL and calculate risk score
def evaluate_url(url):
    print(f"\nEvaluating URL: {url}")
    risk_score = 0
    
    # Apply all checks and accumulate the risk score
    risk_score += check_raw_ip(url)
    risk_score += check_excessive_subdomains(url)
    risk_score += check_lack_of_https(url)
    risk_score += check_long_url_length(url)
    risk_score += check_url_encoding(url)
    risk_score += check_unusual_tlds(url)
    risk_score += check_suspicious_characters(url)
    
    # Print the risk score for the URL
    print(f"Risk score for URL: {risk_score}")
    
    # Interpret the risk score
    if risk_score >= 30:
        print("Risk level: High (Potential phishing or malicious URL detected)")
    elif risk_score >= 20:
        print("Risk level: Medium (Suspicious URL detected)")
    else:
        print("Risk level: Low (URL appears safe)")
    
    return risk_score

if __name__ == "__main__":
    # Test URLs
    urls = [
        "http://192.168.1.1/login",
        "https://sub.sub.sub.example.com/path",
        "http://example.com/login",
        "https://verylongurlwithsuspiciouscharactersandsubdomains.example.com/path/to/resource?query=123",
        "https://example.com/legit-path",
        "http://example.tk/admin",
        "https://example.com/encoded%20path%3Dvalue"
    ]
    
    # Evaluate each URL and display individual risk scores
    for url in urls:
        evaluate_url(url)