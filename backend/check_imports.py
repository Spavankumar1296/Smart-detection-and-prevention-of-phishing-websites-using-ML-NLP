try:
    import flask
    import flask_cors
    import bs4
    import sklearn
    import xgboost
    import requests
    import numpy
    import pandas
    import scipy
    print("All imports successful")
except ImportError as e:
    print(f"Import failed: {e}")
