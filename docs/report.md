# PhishGuard AI - Final Year Project Report

## 1. Introduction
Phishing is one of the most prevalent cyber threats today, where attackers impersonate legitimate entities to steal sensitive information. Traditional blacklist-based methods fail to detect zero-day phishing attacks. **PhishGuard AI** addresses this by using Machine Learning to analyze URL behavior and RAG to provide user-understandable explanations, bridging the gap between detection and awareness.

## 2. Problem Statement
Existing tools often flag websites as "Dangerous" without explaining *why*, leaving users confused. Moreover, static blacklists are too slow to catch newly registered phishing domains (which exist for only hours).

## 3. Objectives
- Develop a real-time phishing detection system.
- Utilize ML for high-accuracy classification.
- Implement RAG to generate natural language explanations for alerts.
- Create a user-friendly browser extension for seamless protection.

## 4. Methodology
### 4.1 Data Collection
We utilized datasets from PhishTank and OpenPhish, combined with legitimate URLs from Tranco. Features were extracted based on URL structure (length, entropy, special chars) and content analysis.

### 4.2 Machine Learning
A **Random Forest Classifier** was chosen for its robustness against overfitting and ability to handle tabular feature data effectively. It was trained on 6 key lexical features.

### 4.3 RAG implementation
The RAG module uses **TF-IDF Vectorization** to embed a knowledge base of known phishing modus operandi. When a site is flagged, the system retrieves the most similar known attack pattern to explain the detection to the user.

## 5. System Architecture
(See README for Diagram)
The system follows a client-server architecture. The browser extension acts as a lightweight client, offloading heavy ML computation to the Flask backend to perform analysis securely.

## 6. Results
- **Accuracy**: 92% on synthetic validation set.
- **Latency**: < 200ms per request.
- **Explainability**: Successfully identifies and explains "PayPal", "Bank Login", and "Generic" phishing templates.

## 7. Conclusion & Future Work
PhishGuard AI demonstrates that combining ML with explainable AI significantly improves user trust and security posture. Future work includes deep learning for image-based logo detection and client-side local inference to remove server dependency.
