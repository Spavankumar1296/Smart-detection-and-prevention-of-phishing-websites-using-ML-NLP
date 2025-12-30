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
from backend.rag import PhishRAG

app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# Load Models
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_engine", "models")
XGB_MODEL_PATH = os.path.join(MODEL_DIR, "xgb_url_model.pkl")

try:
    with open(XGB_MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    print(f"XGBoost Model loaded successfully from {XGB_MODEL_PATH}")
except Exception as e:
    print(f"Error loading XGBoost model: {e}")
    model = None

# Initialize RAG
rag_engine = PhishRAG()

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
        # Proceed with empty features or return error? 
        # For robustness, we might want to skip URL model if it fails but continue with content
        # But for now, let's keep it critical
        features_array = None # Flag to skip model
        # return jsonify({"error": f"Feature extraction failed: {str(e)}"}), 500
    
    # 2. Content Analysis
    print("DEBUG: Starting Content Analysis")
    page_text = data.get('page_text', '')
    content_result = content_features.analyze_content(page_text)
    print(f"DEBUG: Content Analysis result: {content_result}")
    
    # 3. Prediction
    risk_score = 0.0
    is_phishing = False
    
    # A. URL Model Prediction
    url_score = 0.0
    if model and features_array is not None:
        try:
            probs = model.predict_proba(features_array)
            url_score = float(probs[0][1]) # Class 1
            print(f"DEBUG: URL Risk Score: {url_score}")
        except Exception as e:
            print(f"Prediction error (URL Model): {e}")

    # B. Content Model Prediction (already in content_result['ml_score'])
    content_score = content_result.get('ml_score', 0.0)
    
    # C. Heuristics (Forms + Urgency)
    heuristic_score = 0.0
    if data.get('has_login_form') and (content_result['has_urgency'] or content_result['keyword_count'] > 2):
        heuristic_score = 0.8
        content_result['findings'].append("Critical: Login form detected on page with urgent/sensitive text.")
    
    # Combined Score (Weighted Average)
    # Weights: URL (40%), Content ML (40%), Heuristics (20%)
    # If URL model failed, put more weight on content
    if model:
        risk_score = (url_score * 0.4) + (content_score * 0.4) + (heuristic_score * 0.2)
    else:
        risk_score = (content_score * 0.7) + (heuristic_score * 0.3)

    # Threshold
    if risk_score > 0.5:
        is_phishing = True
        
    # 4. RAG Explanation
    rag_context = f"URL: {url}. " + " ".join(content_result['findings'])
    if is_phishing:
        rag_context += " The site has high risk indicators."
        
    rag_response = rag_engine.generate_response(rag_context, risk_score)
    
    response = {
        "url": url,
        "is_phishing": is_phishing,
        "risk_score": float(risk_score),
        "explanation": rag_response['explanation'],
        "details": rag_response['details'],
        "content_findings": content_result['findings']
    }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
