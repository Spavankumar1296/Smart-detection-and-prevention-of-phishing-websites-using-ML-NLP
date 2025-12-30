// Function to extract visible text only
function getVisibleText() {
    return document.body.innerText;
}

// Function to check for login forms
function checkLoginForm() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    return passwordInputs.length > 0;
}

// Function to extract anchor text
function getAnchorTags() {
    const anchors = Array.from(document.querySelectorAll('a'));
    return anchors.map(a => ({
        text: a.innerText,
        href: a.href
    })).slice(0, 50); // Limit to 50 to avoid large payloads
}

// Main logic to listen for messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extractContent") {
        const data = {
            url: window.location.href,
            title: document.title,
            visible_text: getVisibleText().substring(0, 5000), // Limit text length
            has_login_form: checkLoginForm(),
            anchors: getAnchorTags()
        };

        // LOGGING AS REQUESTED
        // If the user manually provided a URL in the popup, log that as the target.
        const targetUrl = request.manualUrl || data.url;
        console.log(`PhishGuard Scanning: ${targetUrl} (Source Page: ${data.url})`);
        console.log("PhishGuard Extracted Data:", data);

        sendResponse(data);
    }
    return true; // Keep channel open for async response
});
