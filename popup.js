// Angell Fractal Security — Popup UI
// Copyright 2025-2026 Nicholas Reid Angell

function getScoreClass(score) {
    if (score < 0.3) return "score-low";
    if (score < 0.7) return "score-mid";
    return "score-high";
}

function getRowClass(stats) {
    if (stats.blocked > 0) return "blocked";
    if (stats.maxThreatScore > 0.3) return "threat";
    return "";
}

function renderDomains(domainStats) {
    const list = document.getElementById("domain-list");

    const domains = Object.entries(domainStats || {})
        .sort((a, b) => b[1].maxThreatScore - a[1].maxThreatScore)
        .slice(0, 20);

    if (domains.length === 0) {
        list.innerHTML = '<div class="empty-state">Monitoring network requests...</div>';
        return;
    }

    list.innerHTML = domains.map(([domain, stats]) => `
        <div class="domain-row ${getRowClass(stats)}">
            <div>
                <div class="domain-name">${domain}</div>
                <div style="font-size:10px;color:#555">${stats.total} requests | ${stats.bounded} bounded | ${stats.escaped} escaped</div>
            </div>
            <div class="domain-stats">
                <div class="threat-score ${getScoreClass(stats.maxThreatScore)}">
                    ${(stats.maxThreatScore * 100).toFixed(0)}%
                </div>
                <div>${stats.blocked > 0 ? '🔴 ' + stats.blocked + ' blocked' : '✓'}</div>
            </div>
        </div>
    `).join("");
}

// Load stats
chrome.runtime.sendMessage({ type: "getStats" }, (response) => {
    if (response && response.domainStats) {
        renderDomains(response.domainStats);
    }
});

// Clear button
document.getElementById("clear-btn").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "clearStats" }, () => {
        renderDomains({});
    });
});

// Auto-refresh every 2 seconds
setInterval(() => {
    chrome.runtime.sendMessage({ type: "getStats" }, (response) => {
        if (response && response.domainStats) {
            renderDomains(response.domainStats);
        }
    });
}, 2000);
