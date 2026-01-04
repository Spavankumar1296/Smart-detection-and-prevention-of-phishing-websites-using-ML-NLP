import re
import os
import pickle
import logging
import math
import numpy as np
from scipy.sparse import hstack

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
        'for', 'it', 'with', 'as', 'by', 'from', 'be', 'are', 'was', 'were', 'have', 'has', 'had',
        'br', 'nbsp', 'quot', 'amp'
    }
    # Allow words > 1 char
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
    if 'password' in text_lower and ('username' in text_lower or 'email' in text_lower or 'user id' in text_lower):
        return 1
    return 0

def detect_safe_context(text):
    """
    Checks for context words that indicate legitimate business/hiring activity.
    """
    safe_terms = ['interview', 'candidate', 'resume', 'job application', 'hiring', 'recruitment', 'newsletter', 'unsubscribe']
    text_lower = text.lower()
    for term in safe_terms:
         if term in text_lower:
             return 1
    return 0

def predict_ml_risk(text, structural_features=None):
    """
    Predicts probability of phishing using the loaded ML model.
    structured_features: list/array of [num_forms, num_inputs, num_external_links, num_scripts, has_password_input]
    Returns: float (0.0 to 1.0)
    """
    if not content_model or not vectorizer:
        return 0.0
    
    # Default structural features if not provided
    if structural_features is None:
        # [num_forms, num_inputs, num_ext_links, num_scripts, has_password_input]
        structural_features = [0, 0, 0, 0, 0] 
        
    try:
        # Preprocess text
        tokens = preprocess_text(text)
        text_clean = " ".join(tokens)
        
        # Vectorize Text (TF-IDF)
        text_features = vectorizer.transform([text_clean])
        
        # Combine with structural features
        # Ensure structural_features is 2D array (1, N)
        struct_array = np.array(structural_features).reshape(1, -1)
        
        # Stack (tfidf is sparse, so we use hstack)
        combined_features = hstack([text_features, struct_array])
        
        # Predict Prob
        probs = content_model.predict_proba(combined_features)
        # Class 1 is Phishing
        return float(probs[0][1])
    except Exception as e:
        logger.error(f"ML Prediction failed: {e}")
        return 0.0

def analyze_content(text, structural_data=None):
    """
    Returns a dictionary of content-based features/findings.
    structural_data: dict containing keys like 'num_forms', 'num_anchors', etc.
    """
    if structural_data is None:
        structural_data = {}

    keyword_count = count_sensitive_keywords(text) if text else 0
    has_urgency = detect_urgency(text) if text else 0
    
    # Use provided 'has_login' or heuristic
    has_login = structural_data.get('has_password_input', 0)
    if not has_login and text:
         has_login = detect_login_form(text)

    has_safe_context = detect_safe_context(text) if text else 0
    
    # Prepare features for ML Model
    # Order must match training: [num_forms, num_inputs, num_external_links, num_scripts, has_password_input]
    # We map available data to this, defaulting to 0
    ml_struct_feats = [
        structural_data.get('num_forms', 0),
        structural_data.get('num_inputs', 0),
        structural_data.get('num_external_links', 0),
        structural_data.get('num_scripts', 0),
        1 if has_login else 0
    ]
    
    ml_score = predict_ml_risk(text, ml_struct_feats) if text else 0.0
    
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
        "has_safe_context": has_safe_context,
        "ml_score": ml_score,
        "findings": findings
    }
