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
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # 1. Feature Extraction
    try:
        url_features = features.extract_features(url)
        # Reshape for scalar prediction (1 sample, N features)
        # Check feature count
        expected_features = len(features.extract_feature_names())
        if len(url_features) != expected_features:
            print(f"Warning: Feature count mismatch. Expected {expected_features}, got {len(url_features)}")
            
        # Create DataFrame for XGBoost (it often prefers DF with column names or DMatrix)
        # But sklearn API wrapper usually accepts numpy array too.
        features_array = np.array(url_features).reshape(1, -1)
        
    except Exception as e:
        return jsonify({"error": f"Feature extraction failed: {str(e)}"}), 500

    # 2. Content Analysis
    print("DEBUG: Starting Content Analysis")
    page_text = data.get('page_text', '')
    try:
        content_result = content_features.analyze_content(page_text)
        print(f"DEBUG: Content Analysis result: {content_result}")
    except Exception as e:
        print(f"ERROR in Content Analysis: {e}")
        # Build a safe fallback
        content_result = {"findings": [], "has_urgency": False} 
    
    # 3. Prediction
    risk_score = 0.0
    is_phishing = False
    
    print("DEBUG: Starting Prediction")
    if model:
        try:
            # Predict class
            prediction = model.predict(features_array)[0]
            # Predict probability
            probs = model.predict_proba(features_array)
            risk_score = float(probs[0][1]) # Probability of class 1 (Phishing)
            is_phishing = bool(prediction == 1)
        except Exception as e:
            print(f"Prediction error: {e}")
            # Fallback
            is_phishing = False
            
    # Adjust risk score based on content findings (Heuristic)
    if content_result['has_urgency']:
        risk_score = min(1.0, risk_score + 0.2)
        if risk_score > 0.5:
             is_phishing = True
             
    # 4. RAG Explanation
    # Combine findings for RAG
    rag_context = f"{url} " + " ".join(content_result['findings'])
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
