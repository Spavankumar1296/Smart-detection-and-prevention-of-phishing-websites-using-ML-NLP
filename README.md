# PhishGuard Hybrid Phishing Detection System

This project implements a hybrid phishing detection system using Machine Learning (URL analysis) and NLP (HTML content analysis). It consists of a Flask backend and a Chrome Extension.

## 1. Backend Setup (Python Flask)

### Prerequisites
- Python 3.8+
- pip

### Installation
1.  Navigate to the `backend` directory:
    ```bash
    cd backend
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Server
Start the Flask API:
```bash
python app.py
```
The server will run at `http://127.0.0.1:5000`.

## 2. Chrome Extension Setup

1.  Open Google Chrome and navigate to `chrome://extensions/`.
2.  Enable **Developer mode** in the top right corner.
3.  Click **Load unpacked**.
4.  Select the `extension` folder from this project.
5.  The PhishGuard extension should now appear in your browser.

## 3. Usage

1.  Ensure the backend server is running.
2.  Navigate to any website you want to check.
3.  Click the PhishGuard extension icon.
4.  The extension will analyze the URL and page content and display a risk score and verdict (Safe, Suspicious, or Phishing).

## Folder Structure
- `backend/`: Flask API, feature extraction logic, and model handling.
- `extension/`: Chrome extension files (manifest, popup, content scripts).
- `models/`: Pre-trained ML models (ensure `.pkl` files are present here).

## System Details
- **URL Model**: XGBoost (analyzes URL structure).
- **Content Model**: Random Forest/SVM (analyzes HTML text and structure).
- **Hybrid Scoring**: `Final Score = 0.7 * URL_Score + 0.3 * Content_Score`.
