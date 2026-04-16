import os
import json
import requests
from datetime import datetime


# ==============================
# PATH CONFIGURATION
# ==============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
RAG_LIVE_PATH = os.path.join(BASE_DIR, "rag_data", "live")

os.makedirs(RAG_LIVE_PATH, exist_ok=True)


# ==============================
# FETCH PHISHTANK DATA
# ==============================

def fetch_phishtank(limit=500):
    """
    Fetch verified phishing URLs from PhishTank
    and save to rag_data/live/phishtank.json
    """

    print("[*] Fetching PhishTank data...")

    url = "https://data.phishtank.com/data/online-valid.json"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()

        results = []

        for item in data[:limit]:
            results.append({
                "source": "PhishTank",
                "url": item.get("url"),
                "target": item.get("target"),
                "verified": item.get("verified"),
                "submission_time": item.get("submission_time"),
                "text": f"""
                Verified Phishing URL detected.
                URL: {item.get("url")}
                Target Brand: {item.get("target")}
                Verified Status: {item.get("verified")}
                Submission Time: {item.get("submission_time")}
                """
            })

        file_path = os.path.join(RAG_LIVE_PATH, "phishtank.json")

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print(f"[✓] PhishTank data saved ({len(results)} entries)")

    except Exception as e:
        print(f"[ERROR] PhishTank fetch failed: {e}")


# ==============================
# UPDATE ALL FEEDS
# ==============================

def update_all_feeds():
    print("\n========== Updating PhishTank Feed ==========")
    print(f"Time: {datetime.now()}\n")

    fetch_phishtank()

    print("\n[✓] PhishTank feed updated successfully.\n")


# ==============================
# RUN DIRECTLY
# ==============================

if __name__ == "__main__":
    update_all_feeds()