import unittest
import json
import sys
import os

# Create tests directory
if not os.path.exists('tests'):
    os.makedirs('tests')

# Add backend to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import app

class TestPhishGuardBackend(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def log(self, message):

        with open("test_log.txt", "a", encoding="utf-8") as f:
            f.write(message + "\n")

    def test_analyze_phishing_content(self):
        """Test with phishing-like content"""
        # Clear log
        with open("test_log.txt", "w", encoding="utf-8") as f:
            f.write("Starting Tests...\n")
            
        payload = {
            "url": "http://paypal-secure-login-update.com",
            "page_text": "Your PayPal account is limited. Please login to verify identity.",
            "title": "PayPal: Account Suspended",
            "has_login_form": True,
            "anchors": []
        }
        
        try:
            response = self.app.post('/analyze', 
                                   data=json.dumps(payload),
                                   content_type='application/json')
            
            data = json.loads(response.data)
            self.log(f"Test Phishing Output: {json.dumps(data, indent=2)}")
            
            if response.status_code == 200 and data['risk_score'] > 0.45:
                 self.log(f"PASS: Phishing/Suspicious Content Detected (Class: {data.get('classification')})")
                 # Verify RAG returned a string explanation (not default safe one)
                 if "safe" not in data['explanation'].lower():
                     self.log("PASS: RAG Explanation verified")
            else:
                 self.log(f"FAIL: Phishing Content Check. Status: {response.status_code}, Data: {data}")
        except Exception as e:
            self.log(f"ERROR: Phishing Test crashed: {e}")

    def test_analyze_safe_content(self):
        """Test with safe content"""
        payload = {
            "url": "http://my-personal-blog-cats.com",
            "page_text": "Welcome to my cat blog. Here are pictures of fluffy kittens.",
            "title": "My Fluffy Cat Blog",
            "has_login_form": False,
            "anchors": []
        }

        
        try:
            response = self.app.post('/analyze', 
                                   data=json.dumps(payload),
                                   content_type='application/json')
            
            data = json.loads(response.data)
            self.log(f"Test Safe Output: {json.dumps(data, indent=2)}")
            
            if response.status_code == 200 and data['classification'] == 'safe':
                 self.log("PASS: Safe Content Detected")
            else:
                 self.log(f"FAIL: Safe Content Check. Status: {response.status_code}, Classification: {data.get('classification')}")
        except Exception as e:
             self.log(f"ERROR: Safe Test crashed: {e}")


if __name__ == '__main__':
    unittest.main()
