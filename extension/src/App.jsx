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
            let pageText = "";

            // 1. Extract Page Text if in extension context
            if (chrome.tabs && chrome.scripting) {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (tab && tab.id) {
                    try {
                        const injectionResults = await chrome.scripting.executeScript({
                            target: { tabId: tab.id },
                            func: () => document.body.innerText,
                        });
                        if (injectionResults && injectionResults[0]) {
                            pageText = injectionResults[0].result || "";
                            // Limit text size for performance
                            pageText = pageText.substring(0, 2000);
                        }
                    } catch (e) {
                        console.warn("Script injection failed:", e);
                    }
                }
            }

            const response = await fetch('http://127.0.0.1:5000/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: currentUrl,
                    page_text: pageText
                }),
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
                <p className="url-text">Target: {currentUrl}</p>

                {!result && (
                    <button onClick={analyzeUrl} disabled={loading} className="scan-btn">
                        {loading ? 'Scanning...' : 'SCAN NOW'}
                    </button>
                )}

                {error && <div className="error">{error}</div>}

                {result && (
                    <div className={`result-card ${result.is_phishing ? 'danger' : 'safe'}`}>
                        <h2>{result.is_phishing ? 'WARNING: PHISHING DETECTED' : 'WEBSITE IS SAFE'}</h2>

                        <div className="score-box">
                            <span>Risk Score:</span>
                            <div className="progress-bar">
                                <div
                                    className="fill"
                                    style={{ width: `${result.risk_score * 100}%`, backgroundColor: result.is_phishing ? '#ff4d4d' : '#4caf50' }}
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
