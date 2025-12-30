import re
import os
import pickle
import logging

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

def count_sensitive_keywords(text):
    """
    Counts occurrences of sensitive keywords often used in phishing.
    """
    keywords = [
        'password', 'credit card', 'ssn', 'social security', 
        'account number', 'verify', 'confirm', 'urgent', 
        'suspend', 'restrict', 'login', 'bank', 'secure'
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
        'please verify', 'account locked', 'action required',
        'final notice', 'warning'
    ]
    text_lower = text.lower()
    for word in urgency_words:
        if word in text_lower:
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
        # Preprocess simple
        text_clean = text.lower()
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
            "ml_score": 0.0,
            "findings": []
        }
    
    keyword_count = count_sensitive_keywords(text)
    has_urgency = detect_urgency(text)
    ml_score = predict_ml_risk(text)
    
    findings = []
    if keyword_count > 2:
        findings.append(f"Found {keyword_count} sensitive keywords.")
    if has_urgency:
        findings.append("Detected urgent or threatening language.")
    if ml_score > 0.6:
        findings.append(f"Content Analysis Model flagged this as suspicious (Score: {ml_score:.2f}).")
        
    return {
        "keyword_count": keyword_count,
        "has_urgency": has_urgency,
        "ml_score": ml_score,
        "findings": findings
    }
