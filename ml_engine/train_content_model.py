import os
import glob
import logging
import pickle
import numpy as np
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from scipy.sparse import hstack
from content_features import preprocess_text

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML_CONTENT_DIR = os.path.join(BASE_DIR, "html_content")
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

CONTENT_MODEL_PATH = os.path.join(MODEL_DIR, "content_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

def extract_features_from_file(filepath):
    """
    Parses HTML file and extracts:
    1. Visible Text
    2. Structural Features: [num_forms, num_inputs, num_scripts, num_external_links, has_password_input]
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        soup = BeautifulSoup(content, 'html.parser')
        
        # 1. Structural Features
        forms = soup.find_all('form')
        num_forms = len(forms)
        
        inputs = soup.find_all('input')
        num_inputs = len(inputs)
        
        scripts = soup.find_all('script')
        num_scripts = len(scripts)
        
        anchors = soup.find_all('a', href=True)
        # Simple check for external links (starts with http and not relative)
        # Note: In offline dataset, href might be mangled or relative, but we do our best.
        num_external_links = 0
        for a in anchors:
            href = a['href'].lower()
            if href.startswith('http'):
                num_external_links += 1
                
        has_password_input = 0
        for inp in inputs:
            if inp.get('type') == 'password' or 'password' in inp.get('name', '').lower():
                has_password_input = 1
                break
                
        structural_features = [num_forms, num_inputs, num_external_links, num_scripts, has_password_input]
        
        # 2. Text Extraction
        # Kill all script and style elements
        for script in soup(["script", "style"]):
            script.extract()    # rip it out

        text = soup.get_text(separator=' ')
        
        return text, structural_features

    except Exception as e:
        logger.warning(f"Error parsing {filepath}: {e}")
        return "", [0, 0, 0, 0, 0]

def load_dataset():
    """
    Loads data from html_content dataset.
    genuine_site_0 -> Label 0
    phishing_site_1 -> Label 1
    """
    logger.info("Loading dataset...")
    
    texts = []
    features_list = []
    labels = []
    
    # Path to folders
    genuine_dir = os.path.join(HTML_CONTENT_DIR, "genuine_site_0")
    phishing_dir = os.path.join(HTML_CONTENT_DIR, "phishing_site_1")
    
    # Load Genuine
    genuine_files = glob.glob(os.path.join(genuine_dir, "*"))
    logger.info(f"Found {len(genuine_files)} genuine samples.")
    
    for fp in genuine_files:
        if os.path.isdir(fp): continue
        text, feats = extract_features_from_file(fp)
        texts.append(" ".join(preprocess_text(text))) # Preprocess immediately
        features_list.append(feats)
        labels.append(0)
        
    # Load Phishing
    phishing_files = glob.glob(os.path.join(phishing_dir, "*"))
    logger.info(f"Found {len(phishing_files)} phishing samples.")
    
    for fp in phishing_files:
        if os.path.isdir(fp): continue
        text, feats = extract_features_from_file(fp)
        texts.append(" ".join(preprocess_text(text)))
        features_list.append(feats)
        labels.append(1)
        
    return texts, np.array(features_list), np.array(labels)

def train():
    logger.info("Starting training pipeline...")
    
    texts, structural_features, y = load_dataset()
    
    if len(texts) == 0:
        logger.error("No data found! Check paths.")
        return

    logger.info("Vectorizing text...")
    vectorizer = TfidfVectorizer(max_features=5000)
    X_text = vectorizer.fit_transform(texts)
    
    logger.info("Combining features...")
    # Stack TF-IDF (sparse) with Structural (dense)
    X_combined = hstack([X_text, structural_features])
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X_combined, y, test_size=0.2, random_state=42)
    
    logger.info("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    logger.info("Evaluation Results:")
    logger.info(classification_report(y_test, y_pred))
    
    logger.info(f"Saving models to {MODEL_DIR}...")
    
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
        
    with open(CONTENT_MODEL_PATH, 'wb') as f:
        pickle.dump(clf, f)
        
    logger.info("Training complete. Models saved.")

if __name__ == "__main__":
    train()
