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
        console.log("PhishGuard Extracted Content:", data);

        sendResponse(data);
    }
    return true; // Keep channel open for async response
});
