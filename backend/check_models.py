import os
import joblib
import sys

sys.stdout.reconfigure(line_buffering=True)

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models')
URL_MODEL_PATH = os.path.join(MODEL_DIR, 'phishguard_final_model.pkl')
CONTENT_MODEL_PATH = os.path.join(MODEL_DIR, 'html_content_model.pkl')
VECTORIZER_PATH = os.path.join(MODEL_DIR, 'html_vectorizer.pkl')

print(f"Checking models in: {MODEL_DIR}")

def load(path, name):
    if not os.path.exists(path):
        print(f"ERROR: {name} not found at {path}")
        return
    try:
        joblib.load(path)
        print(f"SUCCESS: {name} loaded correctly.")
    except Exception as e:
        print(f"ERROR: Failed to load {name}: {e}")

load(URL_MODEL_PATH, "URL Model")
load(CONTENT_MODEL_PATH, "Content Model")
load(VECTORIZER_PATH, "Vectorizer")
