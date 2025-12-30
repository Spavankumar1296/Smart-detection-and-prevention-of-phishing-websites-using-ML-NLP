import re
import math
import urllib.parse
from urllib.parse import urlparse
from collections import Counter
import socket
import datetime

def get_url_length(url):
    return len(str(url))

def count_dots(url):
    return str(url).count('.')

def has_ip_address(url):
    # Regex for IPv4
    ip_pattern = r'(([0-9]{1,3})\.){3}([0-9]{1,3})'
    match = re.search(ip_pattern, str(url))
    return 1 if match else 0

def count_subdomains(url):
    try:
        parsed = urlparse(str(url))
        # hostname might be None if URL is invalid
        if parsed.hostname:
            return parsed.hostname.count('.')
        return 0
    except:
        return 0

def is_https(url):
    try:
        parsed = urlparse(str(url))
        return 1 if parsed.scheme == 'https' else 0
    except:
        return 0

def suspicious_keywords(url):
    keywords = [
        'login', 'verify', 'update', 'secure', 'bank', 'account', 'confirm', 'signin', 'wallet',
        'auth', 'billing', 'support', 'service', 'client', 'payment', 'paypal', 'apple', 'google',
        'microsoft', 'amazon', 'facebook', 'instagram', 'twitter', 'netflix', 'dropbox'
    ]
    url_lower = str(url).lower()
    for key in keywords:
        if key in url_lower:
            return 1
    return 0

def calculate_entropy(url):
    url = str(url)
    if not url:
        return 0
    p, lns = Counter(url), float(len(url))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def count_digits(url):
    return sum(c.isdigit() for c in str(url))

def get_path_length(url):
    try:
        parsed = urlparse(str(url))
        return len(parsed.path)
    except:
        return 0

def get_tld_length(url):
    try:
        parsed = urlparse(str(url))
        if parsed.hostname:
            parts = parsed.hostname.split('.')
            if len(parts) > 1:
                return len(parts[-1])
        return 0
    except:
        return 0

def has_hyphen_in_domain(url):
    try:
        parsed = urlparse(str(url))
        if parsed.hostname and '-' in parsed.hostname:
            return 1
        return 0
    except:
        return 0

def count_tokens(url):
    # Split by common delimiters
    tokens = re.split(r'[/\.-]', str(url))
    return len([t for t in tokens if t])

def count_special_chars(url):
    special_chars = ['@', '?', '=', '%', '&', '_', '-', '~', '+']
    count = 0
    for char in str(url):
        if char in special_chars:
            count += 1
    return count

def is_suspicious_tld(url):
    suspicious_tlds = ['.xyz', '.tk', '.top', '.club', '.gq', '.ml', '.cf', '.ga', '.info', '.work', '.click']
    try:
        parsed = urlparse(str(url))
        if parsed.hostname:
            for tld in suspicious_tlds:
                if parsed.hostname.endswith(tld):
                    return 1
        return 0
    except:
        return 0

def get_domain_age_days(url):
    # Placeholder for domain age. 
    # Real implementation requires WHOIS API which is slow and often rate-limited/paid.
    # For this offline system, we return -1 indicating unknown, or use a heuristic.
    # We could check if it is a known high-traffic domain to assign a high age, else 0.
    return -1

def extract_features(url):
    """
    Extracts numerical features from a URL string.
    Returns: list of feature values
    """
    # Ensure URL is string
    url = str(url)
    
    return [
        get_url_length(url),
        count_dots(url),
        has_ip_address(url),
        count_subdomains(url),
        is_https(url),
        suspicious_keywords(url),
        calculate_entropy(url),
        count_digits(url),
        get_path_length(url),
        get_tld_length(url),
        has_hyphen_in_domain(url),
        count_tokens(url),
        count_special_chars(url),
        is_suspicious_tld(url),
        get_domain_age_days(url)
    ]

def extract_feature_names():
    return [
        'url_length',
        'num_dots',
        'has_ip',
        'num_subdomains',
        'is_https',
        'suspicious_keywords',
        'url_entropy',
        'num_digits',
        'path_length',
        'tld_length',
        'has_hyphen_domain',
        'num_tokens',
        'num_special_chars',
        'is_suspicious_tld',
        'domain_age_days'
    ]

if __name__ == "__main__":
    test_url = "http://secure-login.paypal.com.verify-account.info"
    print(f"Features for {test_url}:")
    print(dict(zip(extract_feature_names(), extract_features(test_url))))
