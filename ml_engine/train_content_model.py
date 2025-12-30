import pandas as pd
import numpy as np
import pickle
import os
import sys
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import logging
from content_features import preprocess_text

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

CONTENT_MODEL_PATH = os.path.join(MODEL_DIR, "content_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

def load_real_data():
    """
    Loads training data from PhiUSIIL dataset (Title column).
    """
    dataset_path = 'datasets/PhiUSIIL_Phishing_URL_Dataset.csv'
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")
        
    logger.info(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path, usecols=['Title', 'label'], on_bad_lines='skip')
    except ValueError:
        # Fallback
        df = pd.read_csv(dataset_path, on_bad_lines='skip')
        if 'Title' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset missing required 'Title' or 'label' columns")
        df = df[['Title', 'label']]

    # Clean data
    df['Title'] = df['Title'].fillna('')
    df['Title'] = df['Title'].astype(str)
    
    # Filter out empty titles
    df = df[df['Title'].str.len() > 2]
    
    # Downsample if too large for quick training
    if len(df) > 50000:
        logger.info(f"Downsampling from {len(df)} to 50,000 for efficiency...")
        # Ensure we keep a balanced set if possible, but simple sample is okay for now
        df = df.sample(n=50000, random_state=42)
        
    logger.info(f"Training on {len(df)} samples.")
    return df

def train():
    logger.info("Starting training pipeline...")
    
    try:
        df = load_real_data()
        
        # --- Golden Data (Synthetic) ---
        # Ensure model learns basic English patterns
        golden_phishing = [
            "Verify your account immediately", "Update your password", "Your account has been suspended",
            "Login to restore access", "Suspicious activity detected", "Confirm your identity",
            "Urgent action required", "Click here to login securely", "PayPal account limited",
            "Bank of America alert", "Wells Fargo security notice", "Netflix payment failed",
            "Apple ID locked", "Microsoft security alert", "Amazon order issue"
        ]
        golden_safe = [
            "Welcome to my personal blog", "Recipe for chocolate cake", "Latest python programming tutorial",
            "Weather forecast for today", "National park guide", "History of the roman empire",
            "Cute cat pictures", "University research paper", "Official documentation",
            "Contact us for support", "About our company", "Terms of service",
            "Privacy policy", "Community forum", "Open source project"
        ]
        
        golden_data = []
        for t in golden_phishing: golden_data.append({'Title': t, 'label': 1})
        for t in golden_safe: golden_data.append({'Title': t, 'label': 0})
        
        # Replicate golden data to give it weight
        golden_df = pd.DataFrame(golden_data)
        # Repeat 100 times to match magnitude of real data roughly or ensure vocabulary inclusion
        golden_df = pd.concat([golden_df]*50, ignore_index=True)
        
        logger.info(f"Augmenting with {len(golden_df)} synthetic samples.")
        
        # Merge
        df = pd.concat([df, golden_df], ignore_index=True)
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        raw_titles = df['Title'].tolist()

        y = df['label']
        
        logger.info("Preprocessing texts...")
        # Apply the same preprocessing as in inference
        processed_texts = [" ".join(preprocess_text(t)) for t in raw_titles]
        
    except Exception as e:
        logger.error(f"Failed to load/process data: {e}")
        return
    
    logger.info("Vectorizing...")
    # TF-IDF Vectorizer
    # We use the same parameters as we want to use in inference, 
    # but since we manual preprocess, we don't need 'english' stop words here if preprocess does it.
    # But keeping max_features is good.
    vectorizer = TfidfVectorizer(max_features=5000)
    X = vectorizer.fit_transform(processed_texts)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Random Forest Classifier
    logger.info("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    logger.info("Evaluation Results:")
    logger.info(classification_report(y_test, y_pred))
    
    logger.info(f"Saving models to {MODEL_DIR}...")
    
    # Save Vectorizer
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
        
    # Save Classifier
    with open(CONTENT_MODEL_PATH, 'wb') as f:
        pickle.dump(clf, f)
        
    logger.info("Training complete. Models saved.")

if __name__ == "__main__":
    train()
