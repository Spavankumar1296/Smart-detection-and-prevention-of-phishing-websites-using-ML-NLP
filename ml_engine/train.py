import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
import sys

# Add parent dir to path to import local modules if needed, though usually same dir is fine
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import features
    import data_loader
except ImportError:
    # If running from root directory
    from ml_engine import features
    from ml_engine import data_loader

def train_model():
    print("Loading data...")
    df = data_loader.load_data("dataset.csv") # Try loading local csv first
    
    print(f"Extracting features for {len(df)} samples...")
    # Apply feature extraction
    X = np.array([features.extract_features(url) for url in df['url']])
    y = df['label'].values
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train
    print("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))
    
    # Save
    model_path = os.path.join("backend", "model.pkl")
    # Ensure backend dir exists
    os.makedirs("backend", exist_ok=True)
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_model()
