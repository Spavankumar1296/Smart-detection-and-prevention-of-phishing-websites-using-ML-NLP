import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class PhishRAG:
    def __init__(self):
        # 1. Knowledge Base of Phishing Patterns
        self.knowledge_base = [
            "This URL mimics PayPal. Phishing sites often use 'paypal' in subdomains to trick users (e.g., paypal-secure.com).",
            "This looks like a fake bank login. Attackers use words like 'verify', 'secure', 'account' to create urgency.",
            "Suspicious use of IP address. Legitimate large sites rarely serve content directly from an IP address.",
            "The URL is very long and contains many subdomains, which is a common technique to hide the actual domain name on mobile devices.",
            "Brand impersonation detected. The URL contains a brand name but is not hosted on the official domain.",
            "Generic phishing pattern. The site asks for sensitive credentials without proper SSL validation or on a suspicious domain."
        ]
        
        # 2. Vectorize the KB
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.kb_vectors = self.vectorizer.fit_transform(self.knowledge_base)

    def retrieve_explanation(self, url_features_text):
        """
        Retrieves the most relevant explanation based on the input text (URL parts + features).
        """
        # Vectorize the query
        query_vec = self.vectorizer.transform([url_features_text])
        
        # Calculate similarity
        similarities = cosine_similarity(query_vec, self.kb_vectors).flatten()
        
        # Get best match
        best_idx = np.argmax(similarities)
        score = similarities[best_idx]
        
        if score < 0.1:
            return "Detected suspicious patterns, but no specific known phishing campaign matched."
            
        return self.knowledge_base[best_idx]

    def generate_response(self, url, risk_score):
        """
        Generates a human-readable explanation based on risk score and KB.
        """
        # 1. If the site is considered SAFE (low risk score), return a safe explanation.
        if risk_score < 0.5:
             return {
                "risk_score": float(risk_score),
                "explanation": "This website appears safe. No known phishing patterns or suspicious characteristics were detected.",
                "details": f"Analysis of {url} completed. Model confidence in safety: {(1 - risk_score)*100:.1f}%."
            }

        # 2. If the site is RISKY, query the KB for *why*.
        # Create a query string from the URL to match against KB
        clean_url = url.replace("https://", "").replace("http://", "").replace(".", " ").replace("-", " ")
        
        explanation = self.retrieve_explanation(clean_url)
        
        return {
            "risk_score": float(risk_score),
            "explanation": explanation,
            "details": f"Analysis of {url} completed. Risk confidence: {risk_score*100:.1f}%."
        }

if __name__ == "__main__":
    rag = PhishRAG()
    # Test Safe URL
    print("Testing Safe URL:")
    print(rag.generate_response("https://www.linkedin.com/feed/", 0.05))
    
    # Test Phishing URL
    print("\nTesting Phishing URL:")
    print(rag.generate_response("http://paypal-secure.verify-account.com", 0.95))
