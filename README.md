# PhishGuard AI 🛡️

**Real-Time Phishing Detection using Machine Learning, NLP, and RAG.**  
*By [Your Name]*

---

## 📌 Project Overview
PhishGuard AI is an advanced cybersecurity tool designed to detect and block phishing websites in real-time. It uses a hybrid approach combining **Machine Learning (Random Forest)** for risk scoring and **Retrieval-Augmented Generation (RAG)** to provide human-readable explanations for *why* a site is dangerous.

### Key Features
- 🚀 **Real-Time Detection**: Analyzes URLs in milliseconds.
- 🧠 **Explainable AI (RAG)**: Tells you *why* a site is unsafe (e.g., "Impersonates PayPal", "Suspicious urgency").
- 🔒 **Privacy Focused**: Analysis happens via a secure API; no browsing history is stored.
- 🌐 **Browser Extension**: Works seamlessly on Chrome/Edge.

---

## 📂 Project Structure
```
PhishGuardAI/
├── backend/            # Flask API & RAG Engine
│   ├── app.py          # Main API Server
│   ├── rag.py          # Explainability Logic
│   └── model.pkl       # Trained ML Model (Generated)
├── ml_engine/          # ML Training & Data
│   ├── features.py     # Feature Extraction Logic
│   ├── train.py        # Model Training Script
│   └── data_loader.py  # Dataset Handling
├── extension/          # Chrome Extension (React)
│   ├── src/            # Frontend Source
│   ├── public/         # Manifest & Icons
│   └── package.json    # Dependencies
└── docs/               # Project Report & Diagrams
```

---

## 🚀 Setup & Installation

### Prerequisities
- Python 3.8+
- Node.js & npm (for building the extension)

### Step 1: Backend Setup
1. Open a terminal in the `PhishGuardAI` folder.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Generate the dataset and train the model:
   ```bash
   python ml_engine/data_loader.py
   python ml_engine/train.py
   ```
4. Start the backend server:
   ```bash
   python backend/app.py
   ```
   *Server will run at `http://127.0.0.1:5000`*

### Step 2: Extension Setup
1. Open a new terminal in `PhishGuardAI/extension`.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build the extension:
   ```bash
   npm run build
   ```
4. Load into Chrome/Edge:
   - Go to `chrome://extensions`
   - Enable **Developer Mode** (top right).
   - Click **Load unpacked**.
   - Select the `PhishGuardAI/extension/dist` folder.

---

## 🧪 Usage
1. Keep the Backend running (`python backend/app.py`).
2. Open any website in your browser.
3. Click the **PhishGuard** extension icon.
4. It will show:
   - **Risk Score**: (e.g., 95.5%)
   - **Status**: SAFE vs PHISHING
   - **Explanation**: "Matches known PayPal phishing pattern."

---

## 🏗️ Architecture
```mermaid
graph TD
    Client[Browser Extension] -->|1. Send URL| API[Backend API (Flask)]
    API -->|2. Extract Features| FE[Feature Extractor]
    API -->|3. Predict Probability| ML[ML Model (RF)]
    API -->|4. Retrieve Context| RAG[RAG Engine]
    RAG -->|5. Query| KB[Knowledge Base]
    ML -->|6. Risk Score| API
    RAG -->|7. Explanation| API
    API -->|8. JSON Response| Client
```

---

## 📊 Tech Stack
- **Frontend**: React.js, Vite, Chrome Extension API
- **Backend**: Python, Flask
- **AI/ML**: Scikit-Learn (Random Forest), TF-IDF, Cosine Similarity
- **Database**: In-memory RAG Vector Store

