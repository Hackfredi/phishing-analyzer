import tldextract

# Global variable to store the total score
total = 0

# Method to check if a raw IP address is present in the URL
def check_raw_ip(url):
    global total 
    
    # Extract the domain from the URL
    extracted = tldextract.extract(url)
    domain = extracted.domain
    
    # Check if the domain is a raw IP address
    if any(part.isdigit() for part in domain.split('.')):
        print(f"Raw IP detected in URL: {url}")
        total += 10  # Add 10 to the total score
    else:
        print(f"No raw IP detected in URL: {url}")
        total += 0  # Add 0 to the total score

if __name__ == "__main__":
    # Test URLs
    urls = [
        "http://192.168.1.1/login",
        "https://example.com/login",
        "http://10.0.0.1/admin",
        "https://google.com/search"
    ]
    
    # Check each URL for raw IP
    for url in urls:
        check_raw_ip(url)
    
    # Print the final total score
    print(f"Total score: {total}")