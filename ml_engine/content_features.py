import re
import os
import pickle
import logging
import math

logger = logging.getLogger(__name__)

# Load Models (Global load to avoid reloading on every request)
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
CONTENT_MODEL_PATH = os.path.join(MODEL_DIR, "content_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

content_model = None
vectorizer = None

try:
    with open(CONTENT_MODEL_PATH, 'rb') as f:
        content_model = pickle.load(f)
    with open(VECTORIZER_PATH, 'rb') as f:
        vectorizer = pickle.load(f)
    print("Content Analysis Models loaded successfully.")
except Exception as e:
    print(f"Warning: Could not load content models: {e}")

def preprocess_text(text):
    """
    Basic NLP preprocessing: lowercase, remove non-alpha, tokenize.
    (Simplified for exam-safe/dependency-free environment)
    """
    if not text:
        return []
    # Lowercase
    text = text.lower()
    # Remove HTML tags (simple regex)
    text = re.sub(r'<[^>]+>', ' ', text)
    # Remove special chars (keep digits and spaces)
    text = re.sub(r'[^a-z0-9\s]', '', text)
    # Tokenize
    tokens = text.split()
    # Remove stop words (basic list)
    stop_words = {
        'the', 'is', 'at', 'which', 'on', 'in', 'and', 'or', 'of', 'to', 'a', 'an', 'that', 'this',
        'for', 'it', 'with', 'as', 'by', 'from', 'be', 'are', 'was', 'were', 'have', 'has', 'had'
    }
    # Allow words > 1 char (e.g. "id", "24")
    tokens = [t for t in tokens if t not in stop_words and len(t) > 1]
    return tokens

def count_sensitive_keywords(text):
    """
    Counts occurrences of sensitive keywords often used in phishing.
    """
    keywords = [
        'password', 'credit card', 'ssn', 'social security', 
        'account number', 'verify', 'confirm', 'urgent', 
        'suspend', 'restrict', 'login', 'bank', 'secure',
        'update', 'billing', 'invoice', 'locked', 'unusual activity'
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
    urgency_patterns = [
        r'immediately', r'24 hours', r'suspended', r'unauthorized', 
        r'verify.*now', r'account.*locked', r'action required',
        r'final notice', r'warning', r'limited time', r'restore access'
    ]
    text_lower = text.lower()
    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            return 1
    return 0

def detect_login_form(text):
    """
    Heuristic to check if text suggests a login form (since we might not have raw HTML).
    """
    text_lower = text.lower()
    # If "password" and ("username" or "email") appear close or in the text
    if 'password' in text_lower and ('username' in text_lower or 'email' in text_lower or 'user id' in text_lower):
        return 1
    return 0

def predict_ml_risk(text):
    """
    Predicts probability of phishing using the loaded ML model.
    Returns: float (0.0 to 1.0)
    """
    if not content_model or not vectorizer or not text:
        return 0.0
    
    try:
        # Preprocess for vectorizer (it usually expects raw string)
        # But we can apply our cleaning first
        tokens = preprocess_text(text)
        text_clean = " ".join(tokens)
        
        # Vectorize
        features = vectorizer.transform([text_clean])
        # Predict Prob
        probs = content_model.predict_proba(features)
        # Class 1 is Phishing
        return float(probs[0][1])
    except Exception as e:
        logger.error(f"ML Prediction failed: {e}")
        return 0.0

def analyze_content(text):
    """
    Returns a dictionary of content-based features/findings.
    """
    if not text:
        return {
            "keyword_count": 0,
            "has_urgency": 0,
            "has_login": 0,
            "ml_score": 0.0,
            "findings": []
        }
    
    keyword_count = count_sensitive_keywords(text)
    has_urgency = detect_urgency(text)
    has_login = detect_login_form(text)
    ml_score = predict_ml_risk(text)
    
    findings = []
    if keyword_count > 0:
        findings.append(f"Found {keyword_count} sensitive keywords.")
    if has_urgency:
        findings.append("Detected urgent or threatening language.")
    if has_login:
        findings.append("Detected possible login form requests.")
    if ml_score > 0.6:
        findings.append(f"Content Analysis Model flagged this as suspicious (Score: {ml_score:.2f}).")
        
    return {
        "keyword_count": keyword_count,
        "has_urgency": has_urgency,
        "has_login": has_login,
        "ml_score": ml_score,
        "findings": findings
    }
