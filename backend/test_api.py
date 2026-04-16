import requests
import json

def test_prediction():
    url = "http://127.0.0.1:5000/predict"
    
    # Test Case 1: Safe URL
    payload_safe = {
        "url": "https://www.google.com",
        "html": "<html><body><h1>Google</h1><form><input type='text'></form></body></html>"
    }
    
    try:
        response = requests.post(url, json=payload_safe)
        print("Status Code:", response.status_code)
        print("Response:", json.dumps(response.json(), indent=2))
    except Exception as e:
        print("Error connecting to backend:", e)

    # Test Case 2: Phishing URL (Simulated)
    payload_phish = {
        "url": "http://secure-login-update-account.com/login.php",
        "html": "<html><body><h1>Login</h1><form><input type='password' name='pass'></form><p>Verify your account immediately.</p></body></html>"
    }
    
    try:
        response = requests.post(url, json=payload_phish)
        print("\nStatus Code:", response.status_code)
        print("Response:", json.dumps(response.json(), indent=2))
    except Exception as e:
        print("Error connecting to backend:", e)

if __name__ == "__main__":
    print("Testing PhishGuard API...")
    test_prediction()
