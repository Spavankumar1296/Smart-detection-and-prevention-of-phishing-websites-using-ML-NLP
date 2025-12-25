import requests
import time
import sys

def test_analyze():
    url = "http://127.0.0.1:5000/analyze"
    payload = {
        "url": "https://www.linkedin.com/feed/",
        "page_text": "Please verify your password immediately."
    }
    try:
        response = requests.post(url, json=payload)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    # Wait for server to potentially start
    time.sleep(2)
    test_analyze()
