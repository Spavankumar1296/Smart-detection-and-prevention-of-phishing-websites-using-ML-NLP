import React, { useState, useEffect } from 'react';
import './index.css';

function App() {
    const [currentUrl, setCurrentUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        // Get current tab URL
        if (chrome.tabs) {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]) {
                    setCurrentUrl(tabs[0].url);
                }
            });
        } else {
            // Fallback for local testing outside extension
            setCurrentUrl("http://test-phishing-url.com");
        }
    }, []);

    const analyzeUrl = async () => {
        setLoading(true);
        setError(null);
        try {
            let extractedData = {
                url: currentUrl,
                page_text: "",
                title: "",
                has_login_form: false,
                anchors: []
            };

            // 1. Extract Page Text via Content Script Message
            if (chrome.tabs) {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (tab && tab.id) {
                    try {
                        const response = await chrome.tabs.sendMessage(tab.id, {
                            action: "extractContent",
                            manualUrl: currentUrl
                        });
                        if (response) {
                            extractedData = {
                                ...extractedData,
                                ...response,
                                url: currentUrl // FORCE USE of manual URL (override content script's url)
                            };
                        }
                    } catch (e) {
                        console.warn("Content script communication failed:", e);
                    }
                }
            }

            const response = await fetch('http://127.0.0.1:5000/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(extractedData),
            });

            if (!response.ok) {
                throw new Error('API request failed');
            }

            const data = await response.json();
            setResult(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="container">
            <header>
                <h1>PhishGuard AI 🛡️</h1>
            </header>

            <div className="content">
                <div className="url-input-container">
                    <label htmlFor="urlInput">Target URL:</label>
                    <input
                        id="urlInput"
                        type="text"
                        value={currentUrl}
                        onChange={(e) => setCurrentUrl(e.target.value)}
                        className="url-input"
                        placeholder="https://example.com"
                    />
                </div>

                {!result && (
                    <button onClick={analyzeUrl} disabled={loading} className="scan-btn">
                        {loading ? 'Scanning...' : 'SCAN NOW'}
                    </button>
                )}

                {error && <div className="error">{error}</div>}

                {result && (
                    <div className={`result-card ${result.classification}`}>
                        <h2>
                            {result.classification === 'phishing' ? 'WARNING: PHISHING DETECTED' :
                                result.classification === 'suspicious' ? 'CAUTION: SUSPICIOUS SITE' :
                                    'WEBSITE IS SAFE'}
                        </h2>

                        <div className="score-box">
                            <span>Risk Score:</span>
                            <div className="progress-bar">
                                <div
                                    className="fill"
                                    style={{
                                        width: `${result.risk_score * 100}%`,
                                        backgroundColor: result.classification === 'phishing' ? '#ff4d4d' :
                                            result.classification === 'suspicious' ? '#f39c12' : '#4caf50'
                                    }}
                                ></div>
                            </div>
                            <span className="score-val">{(result.risk_score * 100).toFixed(1)}%</span>
                        </div>

                        <div className="explanation">
                            <h3>AI Analysis:</h3>
                            <p>{result.explanation}</p>
                        </div>

                        <button onClick={() => setResult(null)} className="reset-btn">Scan Another</button>
                    </div>
                )}
            </div>
        </div>
    );
}

export default App;
