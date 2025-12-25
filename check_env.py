
import sys
try:
    import pandas
    import xgboost
    import sklearn
    with open('env_check.txt', 'w') as f:
        f.write("All imports successful.\n")
except Exception as e:
    with open('env_check.txt', 'w') as f:
        f.write(f"Import Error: {e}\n")
