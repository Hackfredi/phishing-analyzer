import os
import re
import sqlite3
import requests
import whois
from datetime import datetime
import tldextract
from urllib.parse import urlparse
from pathlib import Path
from typing import List, Dict, Optional
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv(Path('config') / 'config1.env')
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
DB_PATH = Path('F:/Engineer/phishing-analyzer/Checks/email_ids.db')  # Confirmed database name
TABLE_NAME = "email_links"  # Confirmed table name
COLUMN_NAME = "link"  # Confirmed column name

if not VIRUSTOTAL_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY not set in config1.env")

# --- Database Functions ---
def fetch_urls_from_db(limit: int = 100) -> List[str]:
    """Fetch URLs from the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(f"SELECT {COLUMN_NAME} FROM {TABLE_NAME} LIMIT ?", (limit,))
        urls = [row[0] for row in cursor.fetchall() if row[0] and isinstance(row[0], str)]
        print(f"✅ Successfully fetched {len(urls)} URLs from database")
        return urls
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        print(f"Please verify:")
        print(f"- Database exists at: {DB_PATH}")
        print(f"- Table '{TABLE_NAME}' exists with column '{COLUMN_NAME}'")
        return []
    finally:
        if 'conn' in locals():
            conn.close()

# --- URL Validation ---
def is_valid_url(url: str) -> bool:
    """Check if URL has a valid format."""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

# --- Phishing Detection Rules ---
def check_blacklisted(url: str) -> bool:
    """Check if domain is blacklisted."""
    domain = urlparse(url).netloc
    # Implementation placeholder - integrate with actual blacklist API
    return False

def check_domain_age(url: str) -> int:
    """Get domain age in days (0 if unknown)."""
    if not is_valid_url(url):
        return 0
    
    domain = tldextract.extract(url).registered_domain
    try:
        whois_info = whois.whois(domain)
        if whois_info.creation_date:
            dates = whois_info.creation_date if isinstance(whois_info.creation_date, list) else [whois_info.creation_date]
            return (datetime.now() - min(dates)).days
    except Exception as e:
        print(f"⚠️ WHOIS check failed for {domain}: {str(e)[:100]}...")
    return 0

def check_suspicious_tld(url: str) -> bool:
    """Check for risky top-level domains."""
    suspicious_tlds = {'.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.ga', '.buzz'}
    ext = tldextract.extract(url)
    return f".{ext.suffix}" in suspicious_tlds

def check_phishing_keywords(url: str) -> bool:
    """Check for phishing keywords in URL."""
    keywords = {
        'verify', 'login', 'secure', 'account', 'update', 'confirm',
        'urgent', 'suspended', 'limited', 'action', 'required'
    }
    return any(keyword in url.lower() for keyword in keywords)

def check_brand_impersonation(url: str) -> bool:
    """Check for brand impersonation in domain."""
    ext = tldextract.extract(url)
    domain = ext.domain + '.' + ext.suffix
    misspellings = {
        'paypal': ['paypai', 'paypal1', 'payypal'],
        'amazon': ['amaz0n', 'amazoon'],
        'ebay': ['eebay', 'ebbay'],
        'apple': ['app1e', 'aple'],
        'microsoft': ['micr0soft', 'mircosoft']
    }
    for brand, variants in misspellings.items():
        if any(v in domain.lower() for v in variants):
            return True
    return False

def check_virustotal(url: str) -> bool:
    """Check URL with VirusTotal API."""
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
            return result.get('positives', 0) > 0
    except Exception as e:
        print(f"⚠️ VirusTotal check failed for {url[:50]}...: {str(e)[:100]}...")
    return False

# --- Scoring System ---
def scan_url(url: str) -> Dict[str, any]:
    """Analyze a URL and return detailed results."""
    if not is_valid_url(url):
        return {'valid': False, 'score': 0, 'details': {}}
    
    details = {
        'blacklisted': check_blacklisted(url),
        'new_domain': check_domain_age(url) < 365,
        'suspicious_tld': check_suspicious_tld(url),
        'phishing_keywords': check_phishing_keywords(url),
        'brand_impersonation': check_brand_impersonation(url),
        'virustotal_flagged': check_virustotal(url)
    }
    
    score = sum([
        2 if details['blacklisted'] else 0,
        1 if details['new_domain'] else 0,
        1 if details['suspicious_tld'] else 0,
        1 if details['phishing_keywords'] else 0,
        2 if details['brand_impersonation'] else 0,
        3 if details['virustotal_flagged'] else 0
    ])
    
    return {
        'valid': True,
        'url': url,
        'score': score,
        'is_phishing': score >= 5,
        'details': details
    }

# --- Main Analysis ---
def analyze_urls(urls: List[str]) -> List[Dict[str, any]]:
    """Analyze multiple URLs."""
    results = []
    for url in urls:
        try:
            result = scan_url(url)
            results.append(result)
        except Exception as e:
            print(f"⚠️ Error analyzing {url[:50]}...: {str(e)[:100]}...")
            results.append({
                'valid': False,
                'url': url,
                'error': str(e)
            })
    return results

def print_results(results: List[Dict[str, any]]):
    """Display analysis results."""
    print("\n" + "="*80)
    print("PHISHING ANALYSIS RESULTS".center(80))
    print("="*80)
    
    for result in results:
        if not result['valid']:
            print(f"\n❌ Invalid URL: {result['url'][:100]}...")
            if 'error' in result:
                print(f"   Error: {result['error'][:200]}...")
            continue
        
        print(f"\n🔗 URL: {result['url'][:100]}...")
        print(f"📊 Score: {result['score']} ({'PHISHING' if result['is_phishing'] else 'Legitimate'})")
        
        print("\nDetailed Findings:")
        for check, value in result['details'].items():
            status = "✔️" if value else "❌"
            print(f"  {status} {check.replace('_', ' ').title()}")


def save_results_to_file(results: List[Dict[str, any]], filename: str = "phishing_analysis_results.txt"):
    """Save analysis results to a file."""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("PHISHING ANALYSIS RESULTS".center(80) + "\n")
        f.write("=" * 80 + "\n\n")
        
        for result in results:
            if not result['valid']:
                f.write(f"❌ Invalid URL: {result['url'][:100]}...\n")
                if 'error' in result:
                    f.write(f"   Error: {result['error'][:200]}...\n")
                f.write("\n")
                continue
            
            f.write(f"🔗 URL: {result['url'][:100]}...\n")
            f.write(f"📊 Score: {result['score']} ({'PHISHING' if result['is_phishing'] else 'Legitimate'})\n")
            
            f.write("\nDetailed Findings:\n")
            for check, value in result['details'].items():
                status = "✔️" if value else "❌"
                f.write(f"  {status} {check.replace('_', ' ').title()}\n")
            
            f.write("\n" + "-" * 80 + "\n\n")
        
        phishing_count = sum(1 for r in results if r.get('is_phishing'))
        f.write(f"🔍 Summary: {phishing_count} phishing URLs detected out of {len(results)} analyzed\n")

# --- Main Execution ---
if __name__ == "__main__":
    print("🚀 Starting Phishing Analyzer")
    print(f"📂 Database: {DB_PATH}")
    print(f"📊 Table: {TABLE_NAME}.{COLUMN_NAME}")
    
    # Fetch only 2 URLs from the database
    urls = fetch_urls_from_db(limit=2)
    if not urls:
        exit()
    
    results = analyze_urls(urls)
    
    # Save results to file instead of printing
    output_file = "phishing_results.txt"
    save_results_to_file(results, output_file)
    print(f"✅ Analysis complete. Results saved to {output_file}")
    