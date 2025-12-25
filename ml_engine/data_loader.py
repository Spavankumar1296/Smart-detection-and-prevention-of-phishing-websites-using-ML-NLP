import pandas as pd
import random

def generate_synthetic_data(num_samples=100):
    """
    Generates a small synthetic dataset for testing purposes.
    """
    phishing_templates = [
        "http://paypal-verification-secure.com",
        "http://secure-login-apple-id.com.verify.me",
        "http://bankofamerica-alert-security.net",
        "http://netflix-payment-update-required.xyz",
        "http://signin.amazon.co.uk.security-check.info",
        "http://facebook-login-verify-account.com",
        "http://google-drive-shared-file.download.net",
        "http://microsoft-outlook-web-access.update.org",
        "http://wells-fargo-online-banking.secure.net",
        "http://instagram-verify-badge-blue.com"
    ]

    legit_templates = [
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.facebook.com",
        "https://www.amazon.com",
        "https://www.wikipedia.org",
        "https://www.reddit.com",
        "https://www.netflix.com",
        "https://www.linkedin.com",
        "https://www.microsoft.com",
        "https://www.twitter.com"
    ]

    data = []
    
    # Generate Phishing
    for _ in range(num_samples // 2):
        base = random.choice(phishing_templates)
        # Add random randomness to make them unique
        url = f"{base}/session/{random.randint(1000,9999)}"
        data.append({"url": url, "label": 1})

    # Generate Legit
    for _ in range(num_samples // 2):
        base = random.choice(legit_templates)
        # Add random path
        url = f"{base}/page/{random.randint(1,100)}"
        data.append({"url": url, "label": 0})
    
    df = pd.DataFrame(data)
    print(f"Generated {len(df)} synthetic samples.")
    return df

def load_data(path=None):
    """
    Loads data from a CSV file or generates synthetic data if path is not provided.
    """
    if path:
        try:
            return pd.read_csv(path)
        except Exception as e:
            print(f"Error loading {path}: {e}")
            return generate_synthetic_data()
    else:
        return generate_synthetic_data()

if __name__ == "__main__":
    df = generate_synthetic_data()
    df.to_csv("dataset.csv", index=False)
    print("Saved to dataset.csv")
