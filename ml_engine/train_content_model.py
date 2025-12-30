import pandas as pd
import numpy as np
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
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
    # Read only relevant columns to save memory
    try:
        df = pd.read_csv(dataset_path, usecols=['Title', 'label'], on_bad_lines='skip')
    except ValueError:
        # Fallback if columns are named differently (e.g. all caps or case sensitivity issues, though we checked headers)
        # Based on headers.txt: 'Title', 'label' exist.
        df = pd.read_csv(dataset_path, on_bad_lines='skip')
        if 'Title' not in df.columns or 'label' not in df.columns:
            raise ValueError("Dataset missing required 'Title' or 'label' columns")
        df = df[['Title', 'label']]

    # Clean data
    df['Title'] = df['Title'].fillna('')
    df['Title'] = df['Title'].astype(str)
    
    # Filter out empty titles or placeholders
    df = df[df['Title'].str.len() > 3]
    
    # Balance dataset if needed? PhiUSIIL is usually balanced-ish or large enough.
    # Let's take a sample to speed up training if it's huge (130k rows is fine, but >500k might be slow)
    if len(df) > 50000:
        logger.info(f"Downsampling from {len(df)} to 50,000 for efficiency...")
        df = df.sample(n=50000, random_state=42)
        
    logger.info(f"Training on {len(df)} samples.")
    return df

def train():
    logger.info("Starting training pipeline using REAL DATA...")
    
    try:
        df = load_real_data()
        X_text = df['Title']
        y = df['label']
    except Exception as e:
        logger.error(f"Failed to load real data: {e}")
        logger.info("Falling back to synthetic data for demonstration purposes...")
        df = create_synthetic_data()
        X_text = df['text']
        y = df['label']
    
    logger.info("Training feature pipeline...")
    # TF-IDF Vectorizer
    # Increased max_features since real data has more vocabulary
    vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
    X = vectorizer.fit_transform(X_text)
    
    # Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X, y)
    
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
