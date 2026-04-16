// popup.js
document.addEventListener('DOMContentLoaded', function () {

    // ── Elements ──────────────────────────────────────────────────
    const loadingDiv      = document.getElementById('loading');
    const resultDiv       = document.getElementById('result');
    const errorDiv        = document.getElementById('error');
    const errorMsg        = document.getElementById('error-msg');

    const verdictCard     = document.getElementById('verdict-card');
    const verdictIcon     = document.getElementById('verdict-icon');
    const verdictLabel    = document.getElementById('verdict-label');
    const verdictSublabel = document.getElementById('verdict-sublabel');
    const scoreValue      = document.getElementById('score-value');
    const riskBarFill     = document.getElementById('risk-bar-fill');
    const explanationText = document.getElementById('explanation-text');


    // ── Show error ────────────────────────────────────────────────
    function showError(message) {
        loadingDiv.classList.add('hidden');
        resultDiv.classList.add('hidden');
        errorDiv.classList.remove('hidden');
        errorMsg.textContent = message;
    }


    // ── Show result in popup ──────────────────────────────────────
    function showResult(data, tabId) {

        if (!data || typeof data.risk_score === 'undefined') {
            showError("Invalid response from backend.");
            return;
        }

        const score   = parseFloat(data.risk_score).toFixed(2);
        const isSafe  = (data.verdict || "").toLowerCase() === "safe";

        loadingDiv.classList.add('hidden');
        errorDiv.classList.add('hidden');
        resultDiv.classList.remove('hidden');

        if (isSafe) {
            verdictCard.className       = 'verdict-card safe';
            verdictIcon.textContent     = '✅';
            verdictLabel.textContent    = 'SAFE';
            verdictSublabel.textContent = 'NO THREATS DETECTED';
            scoreValue.className        = 'score-value safe';
            riskBarFill.className       = 'risk-bar-fill safe';
        } else {
            verdictCard.className       = 'verdict-card phishing';
            verdictIcon.textContent     = '🚨';
            verdictLabel.textContent    = 'PHISHING';
            verdictSublabel.textContent = 'PHISHING SITE DETECTED';
            scoreValue.className        = 'score-value phishing';
            riskBarFill.className       = 'risk-bar-fill phishing';
        }

        scoreValue.textContent      = score + '%';
        explanationText.textContent = data.explanation || 'No explanation provided.';

        setTimeout(() => { riskBarFill.style.width = score + '%'; }, 100);

        // ── If phishing → inject alert into the actual page ───────
        if (!isSafe && tabId) {
            chrome.tabs.sendMessage(tabId, {
                action:      "showResult",
                verdict:     "Phishing",
                score:       score,
                explanation: data.explanation || ""
            });
        }
    }


    // ── Analyze current page ──────────────────────────────────────
    function analyzePage() {
        loadingDiv.classList.remove('hidden');
        resultDiv.classList.add('hidden');
        errorDiv.classList.add('hidden');

        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            const currentTab = tabs[0];
            const url        = currentTab.url;

            if (
                url.startsWith('chrome://') ||
                url.startsWith('edge://')   ||
                url.startsWith('about:')
            ) {
                showError("Cannot analyze browser internal pages.");
                return;
            }

            chrome.tabs.sendMessage(currentTab.id, { action: "getHTML" }, function (response) {

                if (chrome.runtime.lastError) {
                    showError("Could not access page content. Refresh and try again.");
                    return;
                }

                if (response && response.html) {
                    sendToBackend(url, response.html, currentTab.id);
                } else {
                    showError("Failed to retrieve HTML content.");
                }
            });
        });
    }


    // ── Send to Flask backend ─────────────────────────────────────
    function sendToBackend(url, html, tabId) {
        fetch('http://127.0.0.1:5000/predict', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ url: url, html: html })
        })
        .then(response => {
            if (!response.ok) throw new Error('Server error ' + response.status);
            return response.json();
        })
        .then(data => {
            console.log("Backend response:", data);
            showResult(data, tabId);
        })
        .catch(() => showError("Backend unavailable. Make sure the server is running."));
    }


    // ── Retry button ──────────────────────────────────────────────
    document.getElementById('retry-btn').addEventListener('click', analyzePage);

    // ── Start ─────────────────────────────────────────────────────
    analyzePage();
});
