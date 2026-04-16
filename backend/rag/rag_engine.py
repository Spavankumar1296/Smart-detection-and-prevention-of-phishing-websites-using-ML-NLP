import os
import json
import re
import time

from dotenv import load_dotenv
from google import genai

from backend.rag.vector_store import load_faiss_index


# ==============================
# LOAD ENV VARIABLES
# ==============================

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not set in .env file.")

# Initialize Gemini client
client = genai.Client(api_key=GEMINI_API_KEY)


# ==============================
# LOAD FAISS VECTOR STORE
# ==============================

VECTORSTORE = load_faiss_index()


# ==============================
# RETRIEVE CONTEXT FROM FAISS
# ==============================

def retrieve_context(query: str, k: int = 3):

    try:
        docs = VECTORSTORE.similarity_search(query, k=k)

        if not docs:
            return "No relevant threat intelligence found."

        return "\n\n".join([doc.page_content for doc in docs])

    except Exception as e:
        print("FAISS retrieval error:", e)
        return "Threat intelligence retrieval failed."


# ==============================
# GENERATE AI EXPLANATION
# ==============================



def generate_explanation(
    url,
    url_score,
    content_score,
    html_text,
    structural_features
):

    try:

        # Fix None structural features
        if not structural_features:
            structural_features = [[0,0,0,0,0]]
        if not html_text:
            html_text = ""

        combined_score = (0.64 * url_score) + (0.36 * content_score)

        query = f"Phishing analysis for website: {url}"
        context = retrieve_context(query)

        prompt = f"""
You are an advanced cybersecurity threat analysis AI designed to detect phishing websites.

Combine signals from:

• URL detection results
• HTML content analysis
• webpage structural indicators
• threat intelligence retrieved using RAG

Return ONLY JSON in this format:

{{
 "final_risk_score": float,
 "verdict": "Safe" | "Suspicious" | "Phishing",
 "confidence": "Low" | "Medium" | "High",
 "explanation": "Cybersecurity reasoning"
}}

Website URL: {url}

URL Score: {round(url_score,3)}
Content Score: {round(content_score,3)}
Combined Score: {round(combined_score,3)}

Structural Indicators:
Forms: {structural_features[0][0]}
Inputs: {structural_features[0][1]}
Password Fields: {structural_features[0][2]}
Links: {structural_features[0][3]}
Suspicious Keywords: {structural_features[0][4]}

Web Content:
{html_text[:420]}

Threat Intelligence:
{context}
"""

        # ==============================
        # GEMINI API CALL WITH RETRY
        # ==============================

        for attempt in range(3):

            try:

                response = client.models.generate_content(
                    model="gemini-3-flash-preview",
                    contents=prompt
                )

                raw_text = response.text if response.text else ""
                raw_text = raw_text.strip()

                raw_text = re.sub(r"^```json", "", raw_text)
                raw_text = re.sub(r"```$", "", raw_text)
                raw_text = raw_text.strip()

                try:
                    return json.loads(raw_text)

                except Exception:

                    return {
                        "final_risk_score": combined_score,
                        "verdict": "Suspicious",
                        "confidence": "Medium",
                        "explanation": raw_text
                    }

            except Exception as e:

                print(f"Gemini attempt {attempt+1} failed:", e)

                if attempt == 2:
                    raise e

                time.sleep(2)

    except Exception as e:

        print("LLM Error:", e)

        fallback_score = (0.64 * url_score) + (0.34 * content_score)

        return {
            "final_risk_score": fallback_score,
            "verdict": "Suspicious",
            "confidence": "Low",
            "explanation": "Gemini reasoning unavailable. Risk estimated using machine learning models."
        }


# ==============================
# TEST MODE
# ==============================

if __name__ == "__main__":

    print("\n[*] Testing Gemini RAG Engine...\n")

    explanation = generate_explanation(
        url="http://paypa1-secure-login.com",
        url_score=0.82,
        content_score=0.75,
        html_text="Please login to verify your PayPal account immediately.",
        structural_features=[[1, 2, 1, 5, 3]]
    )

    print("\n=== Gemini Explanation ===\n")
    print(json.dumps(explanation, indent=2))