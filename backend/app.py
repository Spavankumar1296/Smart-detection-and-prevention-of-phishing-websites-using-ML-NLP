from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import joblib
import pickle
import numpy as np
import xgboost as xgb

# Add parent directory to path to find ml_engine
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_engine import features, content_features
from backend.rag_explainer import RAGExplainer

app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# Load Models
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_engine", "models")
ENSEMBLE_PATH = os.path.join(MODEL_DIR, "ensemble_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler_model.pkl")

try:
    with open(ENSEMBLE_PATH, 'rb') as f:
        model = pickle.load(f)
    print(f"Ensemble Model loaded successfully from {ENSEMBLE_PATH}")
except Exception as e:
    print(f"Error loading Ensemble model: {e}")
    model = None

try:
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    print(f"Scaler loaded successfully from {SCALER_PATH}")
except Exception as e:
    print(f"Error loading Scaler: {e}")
    scaler = None

# Initialize Offline RAG
# Path needs to be correct relative to where app is run (usually root)
KB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_kb.json")
rag_explainer = RAGExplainer(kb_path=KB_PATH)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running", "model_loaded": model is not None})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    
    # --- LOGGING AS REQUESTED BY USER ---
    print("\n" + "="*50)
    print("DEBUG: Received Analysis Request")
    print(f"URL: {data.get('url')}")
    print(f"Page Title: {data.get('title')}")
    print(f"Has Login Form: {data.get('has_login_form')}")
    # Print a snippet of the text to avoid flooding console
    text_snippet = data.get('page_text', '')[:100] + "..." if data.get('page_text') else "None"
    print(f"Visible Text Snippet: {text_snippet}")
    print(f"Anchors Count: {len(data.get('anchors', []))}")
    print("="*50 + "\n")
    # ------------------------------------

    url = data.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # 1. Feature Extraction (URL Based)
    try:
        url_features = features.extract_features(url)
        # Reshape for scalar prediction (1 sample, N features)
        expected_features = len(features.extract_feature_names())
        if len(url_features) != expected_features:
            print(f"Warning: Feature count mismatch. Expected {expected_features}, got {len(url_features)}")
            
        features_array = np.array(url_features).reshape(1, -1)
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        features_array = None # Flag to skip model
    
    # 2. Content Analysis
    print("DEBUG: Starting Content Analysis")
    page_text = data.get('page_text', '')
    content_result = content_features.analyze_content(page_text)
    print(f"DEBUG: Content Analysis result: {content_result}")
    

    # 3. Prediction
    risk_score = 0.0
    is_phishing = False
    classification = "safe"
    risk_flags = []
    
    # A. URL Model Prediction
    url_score = 0.0
    if model and features_array is not None:
        try:
            # Scale features
            if scaler:
                features_array_scaled = scaler.transform(features_array)
            else:
                features_array_scaled = features_array
                
            probs = model.predict_proba(features_array_scaled)
            url_score = float(probs[0][1]) # Class 1
            print(f"DEBUG: URL Risk Score: {url_score}")
        except Exception as e:
            print(f"Prediction error (URL Model): {e}")
            url_score = 0.0 

    # B. Content Model Prediction (already in content_result['ml_score'])
    content_score = content_result.get('ml_score', 0.0)
    
    # C. Heuristics & Risk Penalties
    heuristic_penalty = 0.0
    
    # C1. URL Heuristics (from features extract)
    # We need to re-extract or check specific feature indices if we want logic here.
    # Alternatively, use the helper functions directly if needed, but we have features_array.
    # Let's map indices from feature_names to get specific values.
    feature_names = features.extract_feature_names()
    try:
        if features_array is not None:
            # Helper to get value by name
            def get_feat(name):
                idx = feature_names.index(name)
                return features_array[0][idx]

            if get_feat('is_suspicious_tld') > 0:
                heuristic_penalty += 0.2
                risk_flags.append("Suspicious Top-Level Domain (TLD) detected.")
                
            if get_feat('has_ip') > 0:
                heuristic_penalty += 0.3
                risk_flags.append("IP Address used in URL (High Risk).")
                
            if get_feat('suspicious_keywords') > 0:
                heuristic_penalty += 0.25
                risk_flags.append("URL contains suspicious security-related keywords.")
                
    except Exception as e:
        print(f"Error checking feature heuristics: {e}")

    # C2. Content Heuristics
    if data.get('has_login_form'):

        # Login form on non-HTTPS is critical
        if 'https' not in url.lower():
             heuristic_penalty += 0.4
             risk_flags.append("CRITICAL: Login form on insecure (HTTP) website.")
        else:
             # Just a login form is suspicious if combined with urgency
             if content_result['has_urgency']:
                 heuristic_penalty += 0.2
                 risk_flags.append("Login form with urgent/threatening language.")

    if content_result['has_urgency']:
        # Base urgency penalty
        heuristic_penalty += 0.1
        risk_flags.append("Urgent or threatening language detected.")
        
    if content_result['keyword_count'] > 0:
         # Scale penalty: 0.05 per keyword, capped at 0.2
         k_penalty = min(0.2, content_result['keyword_count'] * 0.05)
         heuristic_penalty += k_penalty
         risk_flags.append(f"Found {content_result['keyword_count']} sensitive keywords.")
    
    # D. Final Score Calculation (Weighted)
    # Weights: URL Model (50%), Content Model (30%), Heuristics (20% + Additive Penalties)
    base_score = 0.0
    if model:
        base_score = (url_score * 0.5) + (content_score * 0.3)
    else:
        # Fallback if URL model fails
        base_score = content_score * 0.8

    # Add penalties (capped at 1.0)
    risk_score = min(1.0, base_score + heuristic_penalty)
    
    print(f"DEBUG: Base Score: {base_score:.2f}, Penalty: {heuristic_penalty:.2f}, Final: {risk_score:.2f}")

    # E. Classification Thresholds (3-Level)
    # >= 0.75 -> Phishing
    # 0.45 - 0.75 -> Suspicious
    # < 0.45 -> Safe (with safety check)
    
    if risk_score >= 0.75:
        classification = "phishing"
        is_phishing = True
    elif risk_score >= 0.45:
        classification = "suspicious"
        # We set is_phishing to True for "suspicious" to warn the user, 
        # or False depending on how aggressive we want the extension to be.
        # Request says "Low confidence predictions must NOT be labeled safe."
        # So "suspicious" should probably trigger a warning.
        # Let's keep is_phishing=True for suspicious so the extension blocks/warns it.
        is_phishing = True 
    else:
        classification = "safe"
        is_phishing = False
        
        # F. Safe-Label Safety Check
        # If score is low but we have critical flags (shouldn't happen with additive penalty, but just in case)
        if len(risk_flags) > 0 and risk_score > 0.3:
            classification = "suspicious"
            is_phishing = True
            risk_flags.append("Downgraded to Suspicious due to presence of risk flags despite low model score.")

    # 4. RAG Explanation (Offline)
    explanation = "This website appears safe. No known phishing patterns detected."
    if classification != "safe":
        # Construct query for RAG
        query_parts = risk_flags.copy()
        query_parts.extend(content_result['findings'])
        query_parts.append(url)
        
        query = " ".join(query_parts)
        print(f"DEBUG: RAG Query: {query}")
        
        retrieved_text = rag_explainer.get_explanation(query)
        explanation = f"⚠️ **{classification.upper()}**: {retrieved_text}"
        
    response = {
        "url": url,
        "is_phishing": is_phishing,
        "classification": classification,
        "risk_score": float(risk_score),
        "explanation": explanation,
        "details": f"Confidence: {float(risk_score)*100:.1f}%. Level: {classification.upper()}.",
        "content_findings": content_result['findings'],
        "risk_flags": risk_flags
    }
    
    return jsonify(response)



if __name__ == '__main__':
    app.run(debug=True, port=5000)
