import os
import pandas as pd

datasets_dir = 'datasets'
output_file = 'headers.txt'

with open(output_file, 'w') as f:
    for filename in os.listdir(datasets_dir):
        if filename.endswith('.csv'):
            try:
                path = os.path.join(datasets_dir, filename)
                df = pd.read_csv(path, nrows=0)
                f.write(f"File: {filename}\n")
                f.write(f"Columns: {list(df.columns)}\n\n")
            except Exception as e:
                f.write(f"File: {filename} - Error: {e}\n\n")
