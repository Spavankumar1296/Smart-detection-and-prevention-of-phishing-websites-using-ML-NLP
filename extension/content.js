// content.js
// ─────────────────────────────────────────────────────────────────
// Injected into every page by the Chrome extension.
// Does two things:
//   1. Returns the page HTML when popup asks for it
//   2. Injects a full-screen phishing alert overlay into the page
//      when popup tells it the site is phishing
// ─────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {

    // ── Request 1: popup asking for page HTML ─────────────────────
    if (message.action === "getHTML") {
        sendResponse({ html: document.documentElement.outerHTML });
        return true;
    }

    // ── Request 2: popup telling us result ────────────────────────
    if (message.action === "showResult") {
        if (message.verdict === "Phishing") {
            injectPhishingAlert(message.score, message.explanation);
        }
        sendResponse({ ok: true });
        return true;
    }
});


// ── Inject full-screen phishing alert ────────────────────────────
function injectPhishingAlert(score, explanation) {

    // Don't inject twice
    if (document.getElementById("phishguard-overlay")) return;

    // ── Styles ────────────────────────────────────────────────────
    const style = document.createElement("style");
    style.id = "phishguard-styles";
    style.textContent = `
        @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@700;800&display=swap');

        #phishguard-overlay {
            position: fixed;
            inset: 0;
            z-index: 2147483647;
            background: rgba(5, 0, 10, 0.92);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            display: flex;
            align-items: center;
            justify-content: center;
            animation: pg-fadeIn 0.35s ease forwards;
            font-family: 'Syne', sans-serif;
        }

        @keyframes pg-fadeIn {
            from { opacity: 0; }
            to   { opacity: 1; }
        }

        /* scan lines */
        #phishguard-overlay::before {
            content: '';
            position: fixed;
            inset: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 3px,
                rgba(255, 30, 60, 0.04) 3px,
                rgba(255, 30, 60, 0.04) 6px
            );
            pointer-events: none;
            z-index: 1;
        }

        #phishguard-card {
            position: relative;
            z-index: 2;
            background: #0d0008;
            border: 1px solid rgba(255, 30, 60, 0.5);
            border-radius: 20px;
            padding: 44px 40px 36px;
            max-width: 480px;
            width: calc(100vw - 48px);
            text-align: center;
            box-shadow:
                0 0 0 1px rgba(255, 30, 60, 0.1),
                0 0 60px rgba(255, 30, 60, 0.25),
                0 32px 80px rgba(0,0,0,0.8);
            animation: pg-cardIn 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
        }

        @keyframes pg-cardIn {
            from { transform: translateY(28px) scale(0.94); opacity: 0; }
            to   { transform: translateY(0)    scale(1);    opacity: 1; }
        }

        /* top red bar */
        #phishguard-card::before {
            content: '';
            position: absolute;
            top: 0; left: 20px; right: 20px;
            height: 3px;
            background: linear-gradient(90deg, transparent, #ff1e3c, transparent);
            border-radius: 99px;
            animation: pg-barGlow 1.5s ease-in-out infinite alternate;
        }

        @keyframes pg-barGlow {
            from { opacity: 0.6; box-shadow: 0 0 8px  #ff1e3c; }
            to   { opacity: 1.0; box-shadow: 0 0 24px #ff1e3c; }
        }

        #phishguard-icon-ring {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            border: 2px solid rgba(255, 30, 60, 0.6);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin: 0 auto 20px;
            box-shadow: 0 0 30px rgba(255, 30, 60, 0.4);
            animation: pg-iconPulse 1.2s ease-in-out infinite alternate;
        }

        @keyframes pg-iconPulse {
            from { box-shadow: 0 0 16px rgba(255, 30, 60, 0.3); transform: scale(0.97); }
            to   { box-shadow: 0 0 50px rgba(255, 30, 60, 0.6); transform: scale(1.03); }
        }

        #phishguard-tag {
            font-family: 'Space Mono', monospace;
            font-size: 11px;
            letter-spacing: 0.22em;
            color: rgba(255, 30, 60, 0.7);
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        #phishguard-title {
            font-size: 36px;
            font-weight: 800;
            color: #ff1e3c;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            line-height: 1.1;
            text-shadow: 0 0 40px rgba(255, 30, 60, 0.5);
            margin-bottom: 6px;
        }

        #phishguard-subtitle {
            font-family: 'Space Mono', monospace;
            font-size: 12px;
            color: rgba(255, 130, 150, 0.8);
            line-height: 1.6;
            margin-bottom: 20px;
        }

        #phishguard-score-chip {
            display: inline-block;
            background: rgba(255, 30, 60, 0.1);
            border: 1px solid rgba(255, 30, 60, 0.3);
            border-radius: 99px;
            padding: 5px 18px;
            font-family: 'Space Mono', monospace;
            font-size: 13px;
            color: #ff1e3c;
            margin-bottom: 20px;
        }

        #phishguard-explanation {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 30, 60, 0.15);
            border-radius: 10px;
            padding: 14px 16px;
            font-family: 'Space Mono', monospace;
            font-size: 11px;
            color: rgba(200, 140, 150, 0.9);
            line-height: 1.7;
            text-align: left;
            max-height: 100px;
            overflow-y: auto;
            margin-bottom: 24px;
        }

        #phishguard-explanation::-webkit-scrollbar { width: 3px; }
        #phishguard-explanation::-webkit-scrollbar-thumb {
            background: rgba(255,30,60,0.3);
            border-radius: 2px;
        }

        #phishguard-btn-row {
            display: flex;
            gap: 10px;
            justify-content: center;
        }

        .pg-btn {
            border-radius: 10px;
            padding: 11px 24px;
            font-family: 'Syne', sans-serif;
            font-weight: 700;
            font-size: 13px;
            cursor: pointer;
            letter-spacing: 0.04em;
            transition: all 0.2s ease;
            border: none;
        }

        #pg-btn-leave {
            background: #ff1e3c;
            color: #fff;
            box-shadow: 0 4px 20px rgba(255, 30, 60, 0.4);
        }

        #pg-btn-leave:hover {
            background: #ff0030;
            box-shadow: 0 4px 32px rgba(255, 30, 60, 0.6);
            transform: translateY(-1px);
        }

        #pg-btn-dismiss {
            background: transparent;
            color: rgba(200, 140, 150, 0.8);
            border: 1px solid rgba(255, 30, 60, 0.2) !important;
        }

        #pg-btn-dismiss:hover {
            background: rgba(255, 30, 60, 0.08);
            color: #ff8099;
            transform: translateY(-1px);
        }
    `;
    document.head.appendChild(style);

    // ── Overlay HTML ──────────────────────────────────────────────
    const overlay = document.createElement("div");
    overlay.id = "phishguard-overlay";
    overlay.innerHTML = `
        <div id="phishguard-card">
            <div id="phishguard-icon-ring">⚠️</div>
            <div id="phishguard-tag">⚡ Threat Detected by PhishGuard</div>
            <div id="phishguard-title">Phishing<br>Site</div>
            <div id="phishguard-subtitle">
                This website has been flagged as a phishing attempt.<br>
                Do not enter passwords, card details, or personal information.
            </div>
            <div id="phishguard-score-chip">Risk Score: ${parseFloat(score).toFixed(1)}%</div>
            <div id="phishguard-explanation">${explanation || "No explanation provided."}</div>
            <div id="phishguard-btn-row">
                <button class="pg-btn" id="pg-btn-leave">← Leave This Site</button>
                <button class="pg-btn" id="pg-btn-dismiss">Dismiss</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    // ── Leave button → go to browser's new tab page ───────────────
    document.getElementById("pg-btn-leave").addEventListener("click", function () {
        window.location.href = "chrome://newtab";
    });

    // ── Dismiss button → remove overlay ──────────────────────────
    document.getElementById("pg-btn-dismiss").addEventListener("click", function () {
        overlay.style.animation = "pg-fadeOut 0.25s ease forwards";
        overlay.addEventListener("animationend", () => overlay.remove(), { once: true });

        // add fadeOut keyframe dynamically
        const s = document.createElement("style");
        s.textContent = `@keyframes pg-fadeOut { to { opacity: 0; transform: scale(0.97); } }`;
        document.head.appendChild(s);
    });
}
