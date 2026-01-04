import sys
import os
sys.path.append(os.getcwd())
from ml_engine.content_features import analyze_content

# Mocking a standard interview invite
infosys_text = """
Dear Candidate,
Greetings from Infosys!
You have been shortlisted for an interview.
Please confirm your availability for the scheduled time.
You can login to our secure portal to update your profile and view details.
Regards,
Talent Acquisition Team
"""

def test(text):
    print(f"--- Text ---")
    print(text.strip())
    print("\n--- Analysis ---")
    res = analyze_content(text)
    print(f"Keywords Found: {res['keyword_count']}")
    print(f"ML Score: {res['ml_score']}")
    print(f"Findings: {res['findings']}")
    
    # Simulate App Logic roughly
    heuristic_penalty = 0.0
    risk_flags = []
    
    if res['keyword_count'] > 0:
         k_penalty = min(0.2, res['keyword_count'] * 0.05)
         heuristic_penalty += k_penalty
         risk_flags.append("Keywords found")
         
    total_score = (res['ml_score'] * 0.8) + heuristic_penalty # Assuming no URL score for now
    
    print(f"\n--- Simulation ---")
    print(f"Heuristic Penalty: {heuristic_penalty}")
    print(f"Total Score (approx): {total_score}")
    
    classification = "safe"
    if total_score >= 0.75: classification = "phishing"
    elif total_score >= 0.45: classification = "suspicious"
    
    # Safety Check simulation
    if len(risk_flags) > 0 and total_score > 0.3 and classification == "safe":
        print("Safety Check Triggered! Downgrading to SUSPICIOUS.")
        classification = "suspicious"
        
    print(f"Final Classification: {classification.upper()}")

if __name__ == "__main__":
    test(infosys_text)
