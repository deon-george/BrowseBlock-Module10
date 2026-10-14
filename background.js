// Extension Abuse Analyzer - Background Service Worker
// Provides analysis utilities and handles extension lifecycle

chrome.runtime.onInstalled.addListener((details) => {
    console.log('Extension Abuse Analyzer installed:', details.reason);
    
    if (details.reason === 'install') {
        // Initialize with welcome message or setup
        console.log('First time installation');
    }
});

chrome.runtime.onStartup.addListener(() => {
    console.log('Extension Abuse Analyzer started');
});

// Optional: Expose messaging API for future extensions
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getExtensionInfo' && request.extensionId) {
        chrome.management.get(request.extensionId, (extensionInfo) => {
            if (chrome.runtime.lastError) {
                sendResponse({ error: chrome.runtime.lastError.message });
                return;
            }
            sendResponse({ extension: extensionInfo });
        });
        return true; // Keep message channel open for async response
    }
});
