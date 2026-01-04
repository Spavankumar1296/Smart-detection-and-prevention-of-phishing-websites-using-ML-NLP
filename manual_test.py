import sys
import os
# Add parent dir to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_engine.content_features import analyze_content

def verify():
    print("Verifying Hybrid Content Model...")
    
    # Test Case 1: Safe
    text_safe = "Welcome to our sunny gardening blog. We plant flowers and vegetables."
    struct_safe = {'num_forms': 0, 'num_inputs': 0, 'num_external_links': 5, 'num_scripts': 0, 'has_password_input': 0}
    
    # Test Case 2: Phishing
    text_phish = "URGENT: Your account is suspended. Click here to login securely. Update password."
    struct_phish = {'num_forms': 1, 'num_inputs': 2, 'num_external_links': 0, 'num_scripts': 2, 'has_password_input': 1}
    
    print("\n--- Test Case 1: Safe Blog ---")
    res_safe = analyze_content(text_safe, struct_safe)
    print(f"Score: {res_safe['ml_score']:.4f}")
    
    print("\n--- Test Case 2: Phishing ---")
    res_phish = analyze_content(text_phish, struct_phish)
    print(f"Score: {res_phish['ml_score']:.4f}")
    
    if res_safe['ml_score'] < 0.5 and res_phish['ml_score'] > 0.6:
         print("\nSUCCESS: Model behaves as expected.")
    else:
         print("\nWARNING: Model predictions might be off.")

if __name__ == "__main__":
    verify()
