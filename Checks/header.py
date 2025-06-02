import re
from typing import Dict, List

def header(email_headers: str) -> int:
    """
    Analyze email headers for phishing indicators
    Returns:
        1 if likely phishing (count > 3 suspicious indicators)
        0 if likely legitimate
    """
    count = 0
    headers = parse_headers(email_headers)
    
    # Rule 2a: From vs Return-Path mismatch
    if 'from' in headers and 'return-path' in headers:
        from_email = extract_email(headers['from'][0])
        return_email = extract_email(headers['return-path'][0])
        if from_email and return_email and from_email.lower() != return_email.lower():
            count += 1
    
    # Rule 2b: Check SPF/DKIM/DMARC
    auth_results = headers.get('authentication-results', [])
    spf_status = dkim_status = dmarc_status = None
    
    for result in auth_results:
        if 'spf=' in result.lower():
            spf_status = 'pass' if 'spf=pass' in result.lower() else 'fail'
        if 'dkim=' in result.lower():
            dkim_status = 'pass' if 'dkim=pass' in result.lower() else 'fail'
        if 'dmarc=' in result.lower():
            dmarc_status = 'pass' if 'dmarc=pass' in result.lower() else 'fail'
    
    if spf_status != 'pass' or dkim_status != 'pass' or dmarc_status != 'pass':
        count += 1
    
    # Rule 2c: Check Received headers
    if 'received' in headers:
        last_received = headers['received'][-1]  # Get the first hop (last in list)
        suspicious_ip = re.search(r'from\s+\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', last_received, re.I)
        if suspicious_ip:
            # Here you could add IP reputation check
            count += 0.5  # Partial point for suspicious IP
    
    # Rule 2d: Reply-To mismatch
    if 'from' in headers and 'reply-to' in headers:
        from_email = extract_email(headers['from'][0])
        reply_to_email = extract_email(headers['reply-to'][0])
        if from_email and reply_to_email and from_email.lower() != reply_to_email.lower():
            count += 1
    
    # Rule 2e: Fake Message-ID
    if 'message-id' in headers:
        msg_id = headers['message-id'][0]
        domain = extract_domain(msg_id)
        if domain and 'from' in headers:
            from_domain = extract_domain(headers['from'][0])
            if from_domain and domain.lower() != from_domain.lower():
                count += 1
    
    # Rule 2f: Suspicious X-Headers with IP verification
    suspicious_xheaders = {
        'x-mailer': ['unknown', 'spam', 'fake'],
        'x-priority': ['1', 'high'],
        'x-mailing-list': [],
        'x-spam-flag': ['YES']
    }

    # Special handling for X-Originating-IP
    if 'x-originating-ip' in headers:
        ip_header = headers['x-originating-ip'][0]
        ip_address = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_header)
        
        if ip_address:
            ip_address = ip_address.group(0)
            # Get sender domain from From header
            sender_domain = None
            if 'from' in headers:
                sender_email = extract_email(headers['from'][0])
                if sender_email:
                    sender_domain = sender_email.split('@')[-1]
            
            # Verify IP matches expected country for domain
            if sender_domain:
                expected_country = get_expected_country(sender_domain)  # Placeholder
                ip_country = get_ip_country(ip_address)  # Placeholder
                
                if expected_country and ip_country:
                    if expected_country != ip_country:
                        count += 1  # Full point for country mismatch
                else:
                    count += 0.5  # Partial point if we can't verify but IP exists

    # Check other X-Headers
    for xh, patterns in suspicious_xheaders.items():
        if xh in headers and xh != 'x-originating-ip':  # Skip since we handled it above
            value = headers[xh][0].lower()
            if any(p in value for p in patterns) if patterns else True:
                count += 0.5  # Partial point for other suspicious X-headers
    
    return 1 if count > 3 else 0

def parse_headers(header_text: str) -> Dict[str, List[str]]:
    """Parse email headers into a dictionary"""
    headers = {}
    current_header = None
    
    for line in header_text.splitlines():
        if ':' in line:
            current_header, value = line.split(':', 1)
            current_header = current_header.strip().lower()
            headers.setdefault(current_header, []).append(value.strip())
        elif current_header:
            # Handle folded headers (continuation lines)
            headers[current_header][-1] += ' ' + line.strip()
    
    return headers

def extract_email(text: str) -> str:
    """Extract email address from header field"""
    match = re.search(r'[\w\.-]+@[\w\.-]+', text)
    return match.group(0) if match else None

def extract_domain(text: str) -> str:
    """Extract domain from email or Message-ID"""
    email = extract_email(text)
    if email:
        return email.split('@')[-1]
    match = re.search(r'@([\w\.-]+)>?$', text)
    return match.group(1) if match else None

# Placeholder functions for IP and domain-based geo check
def get_expected_country(domain: str) -> str:
    """Dummy implementation — returns expected country based on domain"""
    return "US"  # Example hardcoded return

def get_ip_country(ip: str) -> str:
    """Dummy implementation — returns country for given IP"""
    return "US"  # Example hardcoded return

# Example usage:
if __name__ == "__main__":
    with open('email_headers.txt', 'r') as f:
        headers = f.read()
    
    result = header(headers)
    print(f"Result: {result} (1 = phishing, 0 = legitimate)")
