import re

def count_sensitive_keywords(text):
    """
    Counts occurrences of sensitive keywords often used in phishing.
    """
    keywords = [
        'password', 'credit card', 'ssn', 'social security', 
        'account number', 'verify', 'confirm', 'urgent', 
        'suspend', 'restrict', 'login'
    ]
    count = 0
    text_lower = text.lower()
    for key in keywords:
        count += text_lower.count(key)
    return count

def detect_urgency(text):
    """
    Returns 1 if urgent language is detected, else 0.
    """
    urgency_words = [
        'immediately', '24 hours', 'suspended', 'unauthorized', 
        'please verify', 'account locked', 'action required'
    ]
    text_lower = text.lower()
    for word in urgency_words:
        if word in text_lower:
            return 1
    return 0

def analyze_content(text):
    """
    Returns a dictionary of content-based features/findings.
    """
    if not text:
        return {
            "keyword_count": 0,
            "has_urgency": 0,
            "findings": []
        }
    
    keyword_count = count_sensitive_keywords(text)
    has_urgency = detect_urgency(text)
    
    findings = []
    if keyword_count > 2:
        findings.append(f"Found {keyword_count} sensitive keywords (e.g., password, verify).")
    if has_urgency:
        findings.append("Detected urgent or threatening language.")
        
    return {
        "keyword_count": keyword_count,
        "has_urgency": has_urgency,
        "findings": findings
    }
