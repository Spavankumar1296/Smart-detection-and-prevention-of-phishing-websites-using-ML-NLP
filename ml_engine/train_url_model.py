
import pandas as pd
import numpy as np
import os
import pickle
import joblib
import sys
import logging
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, roc_auc_score
import xgboost as xgb
from features import extract_features, extract_feature_names

# Setup logging
logging.basicConfig(filename='training_process.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

def log(msg):
    print(msg)
    logging.info(msg)

def load_and_merge_data():
    """
    Loads multiple datasets and merges them into a single dataframe.
    """
    log("Loading and merging datasets...")
    
    dfs = []
    
    # 1. PhiUSIIL
    try:
        df1 = pd.read_csv('datasets/PhiUSIIL_Phishing_URL_Dataset.csv', on_bad_lines='skip')
        if 'URL' in df1.columns and 'label' in df1.columns:
            temp = df1[['URL', 'label']].rename(columns={'URL': 'url'})
            dfs.append(temp)
            log(f"Loaded PhiUSIIL: {len(temp)} rows")
    except Exception as e:
        log(f"Error loading PhiUSIIL: {e}")
        
    # 2. URL dataset.csv
    try:
        df2 = pd.read_csv('datasets/URL dataset.csv', on_bad_lines='skip')
        if 'url' in df2.columns and 'type' in df2.columns:
            temp = df2[['url', 'type']].copy()
            # Map types
            temp['label'] = temp['type'].map({'phishing': 1, 'legitimate': 0, 'benign': 0, 'malicious': 1})
            temp.dropna(subset=['label'], inplace=True)
            dfs.append(temp[['url', 'label']])
            log(f"Loaded URL dataset: {len(temp)} rows")
    except Exception as e:
        log(f"Error loading URL dataset: {e}")

    # 3. Phishing URLs.csv (if exists)
    try:
        df3 = pd.read_csv('datasets/Phishing URLs.csv', on_bad_lines='skip')
        if 'url' in df3.columns and 'Type' in df3.columns:
            temp = df3[['url', 'Type']].rename(columns={'Type': 'type'})
             # Map types
            temp['label'] = temp['type'].map({'phishing': 1, 'legitimate': 0, 'benign': 0})
            temp.dropna(subset=['label'], inplace=True)
            dfs.append(temp[['url', 'label']])
            log(f"Loaded Phishing URLs.csv: {len(temp)} rows")
    except Exception as e:
        log(f"Error loading Phishing URLs.csv: {e}")

    if not dfs:
        raise ValueError("No datasets loaded!")
        
    full_df = pd.concat(dfs, ignore_index=True)
    
    # Remove duplicates
    full_df.drop_duplicates(subset=['url'], inplace=True)
    log(f"Total unique URLs: {len(full_df)}")
    
    # Balancing (simple undersampling of majority class)
    phishing = full_df[full_df['label'] == 1]
    safe = full_df[full_df['label'] == 0]
    
    log(f"Class distribution: Phishing={len(phishing)}, Safe={len(safe)}")
    
    min_len = min(len(phishing), len(safe))
    # We want a decent size, if min_len is huge, we might cap it for performance on local machine
    # But for 'exam-safe' and high accuracy, we want as much data as possible within reason.
    # Let's cap at 10k each for 20k total for speed.
    
    target_size = min(min_len, 10000) 
    
    phishing_sample = phishing.sample(n=target_size, random_state=42)
    safe_sample = safe.sample(n=target_size, random_state=42)
    
    balanced_df = pd.concat([phishing_sample, safe_sample])
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    log(f"Balanced dataset size: {len(balanced_df)}")
    return balanced_df

def extract_features_batch(df):
    log("Extracting features (this comes from the new Advanced Feature Engineering logic)...")
    feature_names = extract_feature_names()
    
    X = []
    y = df['label'].values
    urls = df['url'].tolist()
    
    for i, url in enumerate(urls):
        if i % 5000 == 0:
            log(f"Processed {i}/{len(urls)}")
        try:
            feats = extract_features(url)
            X.append(feats)
        except:
            X.append([0]*len(feature_names))
            
    return np.array(X), y, feature_names

def train_ensemble(X, y):
    log("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 1. Random Forest (Optimized)
    log("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=42)
    rf.fit(X_train_scaled, y_train)
    
    # 2. XGBoost
    log("Training XGBoost...")
    xgb_clf = xgb.XGBClassifier(n_estimators=200, learning_rate=0.1, max_depth=10, 
                                use_label_encoder=False, eval_metric='logloss', n_jobs=-1, random_state=42)
    xgb_clf.fit(X_train_scaled, y_train)
    
    # 3. SVM (RBF Kernel) - training on full set might be slow, so we might skip or use LinearSVC if too slow.
    # SVC with RBF is O(n^2), 80k samples is slow. Let's use it but maybe on a subset for the SVM part or rely on RF/XGB dominant ensemble.
    # Actually, for "exam-safe" prompt requesting accuracy, let's include it but maybe restrict iter or use LinearSVC as proxy if needed.
    # We will try standard SVC but if it hangs, user can kill. 80k is borderline.
    # Let's use a slightly smaller subset or just probability=True (needed for soft vote)
    log("Training SVM (may take some time)...")
    # Using probability=True makes it slower.
    svm = SVC(kernel='rbf', probability=True, random_state=42)
    # Train SVM on a smaller sample (e.g. 10k) to ensure it finishes, then use for ensemble
    # Or just wait. Let's wait but log warning.
    svm.fit(X_train_scaled[:10000], y_train[:10000]) 
    
    # Ensemble: Soft Voting
    log("Training Voting Classifier Enseble...")
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb_clf), ('svm', svm)],
        voting='soft'
    )
    ensemble.fit(X_train_scaled, y_train)
    
    # Evaluation
    log("Evaluating Ensemble...")
    y_pred = ensemble.predict(X_test_scaled)
    y_probs = ensemble.predict_proba(X_test_scaled)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_probs)
    
    log(f"\n--- FINAL EVALUATION ---")
    log(f"Accuracy:  {acc:.4f}")
    log(f"Precision: {prec:.4f}")
    log(f"Recall:    {rec:.4f}")
    log(f"F1 Score:  {f1:.4f}")
    log(f"ROC AUC:   {roc:.4f}")
    log("\nConfusion Matrix:")
    log(classification_report(y_test, y_pred))
    
    return {
        'ensemble': ensemble,
        'scaler': scaler,
        'rf': rf, 
        'xgb': xgb_clf,
        'svm': svm
    }

def save_artifacts(models):
    if not os.path.exists('models'):
        os.makedirs('models')
        
    for name, model in models.items():
        path = f"models/{name}_model.pkl"
        with open(path, 'wb') as f:
            pickle.dump(model, f)
        log(f"Saved {name} to {path}")

if __name__ == "__main__":
    try:
        df = load_and_merge_data()
        X, y, feature_names = extract_features_batch(df)
        models = train_ensemble(X, y)
        save_artifacts(models)
        log("Training Pipeline Completed Successfully.")
    except Exception as e:
        log(f"Fatal Error: {e}")
        import traceback
        traceback.print_exc()
