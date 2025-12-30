print("Hello World")
try:
    import flask
    print("Flask imported")
    import xgboost
    print("XGBoost imported")
    import joblib
    print("Joblib imported")
    from sentence_transformers import SentenceTransformer
    print("SentenceTransformer imported")
    import faiss
    print("FAISS imported")
except Exception as e:
    print(f"Import failed: {e}")
