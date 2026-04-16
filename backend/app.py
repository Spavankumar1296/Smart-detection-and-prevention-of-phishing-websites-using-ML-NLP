import os
import re
import warnings
import joblib
import numpy as np

from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

from backend.feature import FeatureExtraction
from backend.rag.rag_engine import generate_explanation

warnings.filterwarnings("ignore")

app = Flask(__name__)
CORS(app)

# =========================================
# PATH CONFIGURATION
# =========================================

BASE_DIR        = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_DIR       = os.path.join(BASE_DIR, "models")

URL_MODEL_PATH  = os.path.join(MODEL_DIR, "phishing_gbc_model.pkl")
HTML_MODEL_PATH = os.path.join(MODEL_DIR, "best_model.pkl")

url_model       = None
html_model      = None


# =========================================
# LOAD MODELS
# =========================================

def load_models():
    global url_model, html_model

    if os.path.exists(URL_MODEL_PATH):
        url_model = joblib.load(URL_MODEL_PATH)
        print("✅ URL model loaded.")
    else:
        print("❌ URL model missing:", URL_MODEL_PATH)

    if os.path.exists(HTML_MODEL_PATH):
        html_model = joblib.load(HTML_MODEL_PATH)
        print("✅ HTML content model loaded (TF-IDF pipeline).")
    else:
        print("❌ HTML content model missing:", HTML_MODEL_PATH)


# =========================================
# VERDICT HELPER — binary output only
# =========================================

def binary_verdict(score: float) -> str:
    return "Safe" if score <= 0.40 else "Phishing"


# =========================================
# TRUSTED DOMAIN WHITELIST
# These domains are always Safe —
# bypasses all ML and LLM analysis
# =========================================

TRUSTED_DOMAINS = [
    # ── Indian Banks ──────────────────────────────────────────────
    r'(^|\.)sbi\.co\.in$',
    r'(^|\.)sbi\.bank\.in$',
    r'onlinesbi\.sbi$',
    r'onlinesbi\.sbi\.bank\.in$',
    r'(^|\.)hdfcbank\.com$',
    r'(^|\.)icicibank\.com$',
    r'(^|\.)axisbank\.com$',
    r'(^|\.)kotak\.com$',
    r'(^|\.)pnbindia\.in$',
    r'(^|\.)bankofbaroda\.in$',
    r'(^|\.)canarabank\.com$',
    r'(^|\.)unionbankofindia\.org$',
    r'(^|\.)indusind\.com$',
    r'(^|\.)yesbank\.in$',
    r'(^|\.)federalbank\.co\.in$',
    r'(^|\.)idfcfirstbank\.com$',
    r'(^|\.)rbl\.co\.in$',

    # ── Indian Government ─────────────────────────────────────────
    r'\.gov\.in$',
    r'\.nic\.in$',
    r'\.edu\.in$',
    r'\.ac\.in$',
    r'(^|\.)incometax\.gov\.in$',
    r'(^|\.)gst\.gov\.in$',
    r'(^|\.)irctc\.co\.in$',
    r'(^|\.)uidai\.gov\.in$',

    # ── Global Banks ──────────────────────────────────────────────
    r'(^|\.)chase\.com$',
    r'(^|\.)bankofamerica\.com$',
    r'(^|\.)wellsfargo\.com$',
    r'(^|\.)citibank\.com$',
    r'(^|\.)barclays\.co\.uk$',
    r'(^|\.)hsbc\.com$',
    r'(^|\.)deutschebank\.com$',
    r'(^|\.)santander\.com$',

    # ── Payments & Finance ────────────────────────────────────────
    r'(^|\.)paypal\.com$',
    r'(^|\.)razorpay\.com$',
    r'(^|\.)paytm\.com$',
    r'(^|\.)phonepe\.com$',
    r'(^|\.)gpay\.com$',
    r'(^|\.)stripe\.com$',
    r'(^|\.)visa\.com$',
    r'(^|\.)mastercard\.com$',

    # ── Big Tech ──────────────────────────────────────────────────
    r'(^|\.)google\.com$',
    r'(^|\.)google\.co\.in$',
    r'(^|\.)microsoft\.com$',
    r'(^|\.)apple\.com$',
    r'(^|\.)amazon\.com$',
    r'(^|\.)amazon\.in$',
    r'(^|\.)linkedin\.com$',
    r'(^|\.)github\.com$',
    r'(^|\.)youtube\.com$',
    r'(^|\.)facebook\.com$',
    r'(^|\.)instagram\.com$',
    r'(^|\.)twitter\.com$',
    r'(^|\.)x\.com$',
    r'(^|\.)whatsapp\.com$',
    r'(^|\.)zoom\.us$',

    # ── Email Providers ───────────────────────────────────────────
    r'(^|\.)gmail\.com$',
    r'(^|\.)outlook\.com$',
    r'(^|\.)yahoo\.com$',
    r'(^|\.)protonmail\.com$',
]

def check_trusted_domain(url):
    """
    Returns (True, host) if the URL belongs to a whitelisted
    trusted domain, otherwise (False, None).
    """
    try:
        host = urlparse(url).netloc.lower()
        # strip port if present e.g. example.com:8080
        host = host.split(":")[0]
        for pattern in TRUSTED_DOMAINS:
            if re.search(pattern, host):
                return True, host
    except Exception:
        pass
    return False, None


# =========================================
# PIRACY URL BLOCKLIST
# =========================================

PIRACY_PATTERNS = [
    r'movierulz', r'tamilrockers', r'filmyzilla',
    r'123movies',  r'fmovies',     r'putlocker',
    r'yts\.',      r'rarbg',       r'thepiratebay',
    r'1337x',      r'kickass',     r'torrentz',
    r'primewire',  r'hdmovieshub', r'bollyflix',
    r'vegamovies', r'9xmovies',    r'jiorockers',
]

def check_url_blocklist(url):
    url_lower = url.lower()
    for pattern in PIRACY_PATTERNS:
        if re.search(pattern, url_lower):
            return True, pattern
    return False, None


# =========================================
# URL FEATURE EXTRACTION
# =========================================

def extract_url_features(url):
    try:
        obj      = FeatureExtraction(url)
        features = obj.getFeaturesList()
        return np.array(features).reshape(1, 30)
    except Exception as e:
        print("URL feature extraction error:", e)
        return np.zeros((1, 30))


# =========================================
# HTML PREPROCESSING  (matches train.py)
# =========================================

def clean_html(text):
    urls = re.findall(r'(?:href|src|action)=["\']([^"\']{4,})["\']', text, re.IGNORECASE)
    url_tokens = " ".join(urls)

    flags = ""

    phishing_indicators = [
        (r'<form',             "HAS_FORM"),
        (r'<iframe',           "HAS_IFRAME"),
        (r'password',          "HAS_PASSWORD"),
        (r'base64,',           "HAS_BASE64"),
        (r'window\.location',  "HAS_REDIRECT"),
        (r'document\.cookie',  "HAS_COOKIE_ACCESS"),
        (r'eval\s*\(',         "HAS_EVAL"),
        (r'\.exe|\.zip|\.rar', "HAS_DOWNLOAD_LINK"),
        (r'<input',            "HAS_INPUT"),
        (r'login|signin',      "HAS_LOGIN"),
    ]
    for pattern, flag in phishing_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            flags += f" {flag}"

    piracy_indicators = [
        (r'download|torrent|magnet:',                   "HAS_TORRENT"),
        (r'watch.{0,20}(free|online|hd|full)',          "HAS_STREAM"),
        (r'1080p|720p|480p|bluray|webrip|hdcam',        "HAS_PIRACY_QUALITY"),
        (r'movierulz|tamilrockers|filmyzilla|9xmovies', "KNOWN_PIRACY_SITE"),
        (r'\.torrent|magnet:\?xt',                      "HAS_TORRENT_LINK"),
        (r'popup|popunder|onclick.*window\.open',       "HAS_POPUP_ADS"),
    ]
    for pattern, flag in piracy_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            flags += f" {flag}"

    text = re.sub(r'base64,[A-Za-z0-9+/=]{50,}', ' ', text)
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', text, flags=re.DOTALL | re.IGNORECASE)

    script_keywords = []
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE):
        words = re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]{3,}', m.group(1))
        script_keywords.extend(words[:60])
    script_text = " ".join(script_keywords)

    text = re.sub(r'<([a-zA-Z][a-zA-Z0-9]*)[^>]*>', r' TAG_\1 ', text)
    text = re.sub(r'</[^>]+>', ' ', text)
    text = re.sub(r'&[a-zA-Z#0-9]+;', ' ', text)
    text = re.sub(r'[^a-zA-Z0-9\s._/:-]', ' ', text)

    combined = " ".join([text, url_tokens, script_text, flags])
    combined = re.sub(r'\s+', ' ', combined).strip()
    return combined.lower()


# =========================================
# URL-ONLY ANALYSIS
# Called when HTML is unavailable
# =========================================

def analyze_url_only(url):
    print("⚠ HTML unavailable — running URL-only analysis")

    url_features  = extract_url_features(url)
    probabilities = url_model.predict_proba(url_features)[0]
    url_prob      = float(probabilities[0])

    print("===== URL MODEL (URL-only mode) =====")
    print("Phishing probability:", url_prob)
    print("Safe probability    :", float(probabilities[1]))
    print("=====================================\n")

    llm_result = generate_explanation(
        url=url,
        url_score=url_prob,
        content_score=0.0,
        html_text="HTML content unavailable. Analysis based on URL signals only.",
        structural_features=None
    )

    llm_score = llm_result.get("final_risk_score")

    if llm_score is None:
        final_score = url_prob
    else:
        final_score = (0.7 * url_prob) + (0.3 * float(llm_score))

    confidence  = llm_result.get("confidence", "Low")
    explanation = llm_result.get("explanation", "")

    warning_note = (
        "\n\n⚠ Warning: Web content was unavailable for this page "
        "(e.g. page blocked content scripts, or loaded dynamically). "
        "This result is based on URL analysis only and may be less accurate."
    )

    return {
        "risk_score":        float(round(final_score * 100, 2)),
        "verdict":           binary_verdict(final_score),
        "confidence":        str(confidence),
        "explanation":       str(explanation) + warning_note,
        "url_score":         float(round(url_prob * 100, 2)),
        "html_score":        None,
        "ml_combined_score": float(round(url_prob * 100, 2)),
        "html_unavailable":  True
    }


# =========================================
# MAIN PREDICTION ROUTE
# =========================================

@app.route("/predict", methods=["POST"])
def predict():

    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        url  = data.get("url")
        html = data.get("html", "")

        if not url:
            return jsonify({"error": "Missing url"}), 400

        html_available = bool(html and len(html.strip()) > 200)

        print("\n===== REQUEST RECEIVED =====")
        print("URL         :", url)
        print("HTML status :", "available" if html_available else "UNAVAILABLE")
        print("============================\n")

        # ===============================
        # STEP 0A: TRUSTED DOMAIN CHECK
        # Always runs first — if trusted,
        # skip ALL analysis immediately
        # ===============================

        is_trusted, trusted_host = check_trusted_domain(url)

        if is_trusted:
            print(f"✅ TRUSTED DOMAIN: {trusted_host} — skipping ML analysis")
            return jsonify({
                "risk_score":        2.0,
                "verdict":           "Safe",
                "confidence":        "High",
                "explanation":       (
                    f"This URL belongs to a verified trusted domain ({trusted_host}). "
                    f"It is a known legitimate website and has been whitelisted. "
                    f"No further analysis was required."
                ),
                "url_score":         2.0,
                "html_score":        2.0,
                "ml_combined_score": 2.0,
                "html_unavailable":  False
            })

        # ===============================
        # STEP 0B: PIRACY BLOCKLIST
        # ===============================

        is_piracy, matched_pattern = check_url_blocklist(url)

        if is_piracy:
            print(f"🏴‍☠️ PIRACY DETECTED: '{matched_pattern}'")
            return jsonify({
                "risk_score":        95.0,
                "verdict":           "Phishing",
                "confidence":        "High",
                "explanation": (
                    f"This URL matches a known piracy/malicious site pattern: '{matched_pattern}'. "
                    f"These sites distribute illegal content and commonly deliver malicious ads, "
                    f"forced redirects, and drive-by malware downloads."
                ),
                "url_score":         95.0,
                "html_score":        None,
                "ml_combined_score": 95.0,
                "html_unavailable":  False
            })

        # ===============================
        # URL-ONLY FALLBACK
        # ===============================

        if not html_available:
            result = analyze_url_only(url)
            print("===== BACKEND RESPONSE (URL-only) =====")
            print(result)
            print("=======================================\n")
            return jsonify(result)

        # ===============================
        # STEP 1: URL MODEL
        # ===============================

        url_features  = extract_url_features(url)
        probabilities = url_model.predict_proba(url_features)[0]
        url_prob      = float(probabilities[0])

        print("===== URL MODEL =====")
        print("Phishing probability:", url_prob)
        print("Safe probability    :", float(probabilities[1]))
        print("=====================\n")

        # ===============================
        # STEP 2: HTML CONTENT MODEL
        # ===============================

        cleaned_html = clean_html(html)
        html_proba   = html_model.predict_proba([cleaned_html])[0]
        content_prob = float(html_proba[1])

        print("===== HTML CONTENT MODEL =====")
        print("Genuine  probability:", float(html_proba[0]))
        print("Phishing probability:", content_prob)
        print("==============================\n")

        piracy_flags_found = sum([
            "has_torrent"        in cleaned_html,
            "has_stream"         in cleaned_html,
            "has_piracy_quality" in cleaned_html,
            "known_piracy_site"  in cleaned_html,
            "has_torrent_link"   in cleaned_html,
        ])
        if piracy_flags_found >= 3:
            print(f"⚠ {piracy_flags_found} piracy signals — boosting content score")
            content_prob = min(1.0, content_prob + 0.35)

        # ===============================
        # STEP 3: ML SCORE FUSION
        # ===============================

        combined_ml_score = (0.64 * url_prob) + (0.36 * content_prob)

        # ===============================
        # STEP 4: RAG + LLM REASONING
        # ===============================

        llm_result = generate_explanation(
            url=url,
            url_score=url_prob,
            content_score=content_prob,
            html_text=cleaned_html,
            structural_features=None
        )

        llm_score = llm_result.get("final_risk_score")

        if llm_score is None:
            final_score = combined_ml_score
        else:
            final_score = (0.8 * combined_ml_score) + (0.2 * float(llm_score))

        confidence  = llm_result.get("confidence", "Medium")
        explanation = llm_result.get("explanation", "")

        result = {
            "risk_score":        float(round(final_score       * 100, 2)),
            "verdict":           binary_verdict(final_score),
            "confidence":        str(confidence),
            "explanation":       str(explanation),
            "url_score":         float(round(url_prob          * 100, 2)),
            "html_score":        float(round(content_prob      * 100, 2)),
            "ml_combined_score": float(round(combined_ml_score * 100, 2)),
            "html_unavailable":  False
        }

        print("===== BACKEND RESPONSE =====")
        print(result)
        print("============================\n")

        return jsonify(result)

    except Exception as e:
        print("🔥 ERROR:", e)
        return jsonify({"error": str(e)}), 500


# =========================================
# START SERVER
# =========================================

if __name__ == "__main__":
    load_models()
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )