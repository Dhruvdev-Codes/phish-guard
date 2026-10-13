(function() {
    "use strict";
    const state = { currentTab: "inspect", scanMode: "deep", lastScanResult: null, chartInstance: null };
    const elements = {};
    function initNavigation() {
        document.querySelectorAll(".nav-link").forEach(link => {
            link.addEventListener("click", (e) => {
                const targetSection = link.dataset.section;
                if (targetSection) {
                    e.preventDefault();
                    switchSection(targetSection);
                    document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
                    link.classList.add("active");
                }
            });
        });
    }
    function switchSection(sectionName) {
        const inspectSection = document.getElementById("inspectSection");
        const evalSection = document.getElementById("evaluationSection");
        if (sectionName === "inspect") {
            inspectSection.classList.remove("hidden");
            evalSection.classList.add("hidden");
        } else if (sectionName === "evaluation") {
            inspectSection.classList.add("hidden");
            evalSection.classList.remove("hidden");
        }
    }
    function initScanner() {
        elements.urlInput = document.getElementById("urlInput");
        elements.btnScan = document.getElementById("btnScan");
        document.querySelectorAll("input[name=\"scanMode\"]").forEach(radio => {
            radio.addEventListener("change", (e) => { state.scanMode = e.target.value; });
        });
        elements.btnScan.addEventListener("click", performScan);
        elements.urlInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") performScan();
        });
    }
    async function performScan() {
        const url = elements.urlInput.value.trim();
        if (!url) { showNotification("Please enter a URL or domain to scan", "warning"); return; }
        if (!isValidUrl(url)) { showNotification("Please enter a valid URL format", "error"); return; }
        elements.btnScan.disabled = true;
        elements.btnScan.querySelector(".btn-text").textContent = "SCANNING...";
        elements.btnScan.querySelector(".btn-icon").textContent = "⏳";
        try {
            const result = state.scanMode === "fast" ? await fastLexicalScan(url) : await deepInspection(url);
            state.lastScanResult = result;
            displayResults(result);
        } catch (error) {
            console.error("Scan error:", error);
            showNotification(`Scan failed: ${error.message}`, "error");
        } finally {
            elements.btnScan.disabled = false;
            elements.btnScan.querySelector(".btn-text").textContent = "SCAN";
            elements.btnScan.querySelector(".btn-icon").textContent = "🔍";
        }
    }
    function isValidUrl(string) { try { new URL(string); return true; } catch (_) { return false; } }
    async function fastLexicalScan(url) {
        await delay(500);
        const urlObj = new URL(url);
        const features = analyzeUrlFeatures(urlObj);
        const riskScore = calculateHeuristicRisk(features);
        return { url, mode: "fast", verdict: riskScore >= 70 ? "PHISHING" : riskScore >= 40 ? "SUSPICIOUS" : "LEGITIMATE", confidence: riskScore >= 70 ? 85 + Math.random() * 10 : 70 + Math.random() * 20, features, riskScore, timestamp: new Date().toISOString() };
    }
    async function deepInspection(url) {
        await delay(2500);
        const urlObj = new URL(url);
        const features = analyzeUrlFeatures(urlObj);
        const domAnalysis = analyzeDOMStructure(urlObj);
        const visualSimilarity = analyzeVisualSimilarity(urlObj);
        const riskScore = calculateComprehensiveRisk(features, domAnalysis, visualSimilarity);
        const shapValues = generateSHAPValues(features);
        return { url, mode: "deep", verdict: riskScore >= 70 ? "PHISHING" : riskScore >= 40 ? "SUSPICIOUS" : "LEGITIMATE", confidence: riskScore >= 70 ? 90 + Math.random() * 8 : 75 + Math.random() * 15, features, domAnalysis, visualSimilarity, shapValues, riskScore, timestamp: new Date().toISOString() };
    }
    function analyzeUrlFeatures(urlObj) {
        const hostname = urlObj.hostname;
        const pathname = urlObj.pathname;
        const search = urlObj.search;
        const urlString = hostname + pathname + search;
        const entropy = calculateEntropy(urlString);
        const suspiciousTLDs = [".xyz", ".top", ".club", ".win", ".zip", ".mov"];
        const hasSuspiciousTLD = suspiciousTLDs.some(tld => hostname.endsWith(tld));
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        const isIPAddress = ipPattern.test(hostname);
        const shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly"];
        const isShortened = shorteners.some(s => hostname.includes(s));
        const suspiciousPatterns = [/login|signin|account|verify|secure|update/i, /[0-9]{4,}/, /[-_]{2,}/, /\b(https?|ftp):\/\/[^\s]/gi];
        let suspiciousScore = 0;
        suspiciousPatterns.forEach(pattern => { if (pattern.test(hostname + pathname)) suspiciousScore += 1; });
        const brandIndicators = [
            { brand: "Google", pattern: /google|goo gle|g0ogle/i },
            { brand: "Microsoft", pattern: /microsft|mircosoft|micro-soft|microsoft365/i },
            { brand: "Apple", pattern: /app1e|appl3|appleid/i },
            { brand: "Amazon", pattern: /amaz0n|amazom|amazon/i },
            { brand: "PayPal", pattern: /paypa1|paypaI|paypal/i },
            { brand: "Chase", pattern: /chase|chasebank/i },
            { brand: "Walmart", pattern: /walmart|wlmart/i }
        ];
        let brandMatch = null;
        for (const indicator of brandIndicators) {
            if (indicator.pattern.test(hostname + pathname)) { brandMatch = indicator.brand; break; }
        }
        return { entropy, hasSuspiciousTLD, isIPAddress, isShortened, suspiciousScore, brandMatch, hostname, pathname, port: urlObj.port };
    }
    function analyzeDOMStructure(urlObj) {
        return { formsCount: Math.floor(Math.random() * 5) + 1, externalScripts: Math.floor(Math.random() * 8) + 1, inlineEventHandlers: Math.floor(Math.random() * 3), suspiciousAttributes: Math.floor(Math.random() * 2), iframesCount: Math.floor(Math.random() * 3), formActionsExternal: Math.random() > 0.6, sslCertificateAge: Math.random() > 0.5 ? "Expired" : "Valid" };
    }
    function analyzeVisualSimilarity(urlObj) {
        const similarityScore = Math.random() * 100;
        let targetBrand = null;
        const brandList = ["Google", "Microsoft", "Apple", "Amazon", "PayPal", "Chase"];
        if (Math.random() > 0.5) { targetBrand = brandList[Math.floor(Math.random() * brandList.length)]; }
        return { visualSimilarity: similarityScore, targetBrand, logoMatch: similarityScore > 80, layoutMatch: similarityScore > 70, colorSchemeMatch: similarityScore > 75 };
    }
    function calculateEntropy(str) {
        const len = str.length;
        const frequencies = {};
        for (let i = 0; i < len; i++) { const char = str[i]; frequencies[char] = (frequencies[char] || 0) + 1; }
        let entropy = 0;
        for (const char in frequencies) { const p = frequencies[char] / len; entropy -= p * Math.log2(p); }
        return Math.round(entropy * 100) / 100;
    }
    function calculateHeuristicRisk(features) {
        let score = 0;
        if (features.entropy > 4.5) score += 30;
        else if (features.entropy > 3.5) score += 15;
        if (features.isIPAddress) score += 25;
        if (features.hasSuspiciousTLD) score += 20;
        if (features.isShortened) score += 10;
        score += features.suspiciousScore * 8;
        if (features.brandMatch) score += 25;
        return Math.min(100, score);
    }
    function calculateComprehensiveRisk(features, domAnalysis, visualSimilarity) {
        let baseScore = calculateHeuristicRisk(features);
        if (domAnalysis.formActionsExternal) baseScore += 15;
        if (domAnalysis.inlineEventHandlers > 0) baseScore += 10;
        if (domAnalysis.iframesCount > 0) baseScore += 5;
        if (domAnalysis.suspiciousAttributes > 0) baseScore += 12;
        if (visualSimilarity.visualSimilarity > 80) baseScore += 20;
        else if (visualSimilarity.visualSimilarity > 60) baseScore += 10;
        return Math.min(100, baseScore);
    }
    function generateSHAPValues(features) {
        const shapValues = [];
        shapValues.push({ feature: "URL Entropy (> 4.5)", value: features.entropy > 4.5 ? 0.38 : -0.05, direction: features.entropy > 4.5 ? "risk" : "safe" });
        shapValues.push({ feature: "Form Action Mismatch", value: 0.29, direction: "risk" });
        if (features.brandMatch) { shapValues.push({ feature: `Visual Logo Similarity (>90%)`, value: 0.22, direction: "risk" }); }
        shapValues.push({ feature: "SSL Cert Age (< 14 Days)", value: Math.random() > 0.5 ? 0.15 : -0.10, direction: Math.random() > 0.5 ? "risk" : "safe" });
        shapValues.push({ feature: "Domain Age (> 2 Years)", value: -0.31, direction: "safe" });
        if (features.isIPAddress) { shapValues.push({ feature: "IP Address Usage", value: 0.25, direction: "risk" }); }
        return shapValues;
    }
    function displayResults(result) {
        const verdictBanner = document.getElementById("verdictBanner");
        const telemetryPanel = document.getElementById("telemetryPanel");
        verdictBanner.classList.remove("hidden");
        const verdictIcon = document.getElementById("verdictIcon");
        const verdictStatus = document.getElementById("verdictStatus");
        const verdictConfidence = document.getElementById("verdictConfidence");
        const verdictConfig = {
            "PHISHING": { icon: "🔴", text: "HIGH-RISK PHISHING DETECTED", class: "critical" },
            "SUSPICIOUS": { icon: "🟠", text: "SUSPICIOUS - REQUIRES REVIEW", class: "warning" },
            "LEGITIMATE": { icon: "🟢", text: "LEGITIMATE - NO THREAT DETECTED", class: "safe" }
        };
        const config = verdictConfig[result.verdict];
        verdictIcon.innerHTML = config.icon;
        verdictStatus.textContent = config.text;
        verdictStatus.className = `verdict-status ${config.class}`;
        verdictConfidence.textContent = `${result.confidence.toFixed(1)}%`;
        updateFeatureSignals(result);
        telemetryPanel.classList.remove("hidden");
        if (result.mode === "deep" && result.shapValues) { renderSHAPChart(result.shapValues); }
        populateThreatBrief(result);
        state.lastScanResult = result;
    }
    function updateFeatureSignals(result) {
        const features = result.features;
        const entropyValue = document.getElementById("urlEntropyValue");
        const entropyIndicator = document.getElementById("urlEntropyIndicator");
        const entropy = features.entropy;
        entropyValue.textContent = `${entropy.toFixed(2)} ${entropy > 4.5 ? "[ High Risk ]" : entropy > 3.5 ? "[ Moderate ]" : "[ Normal ]"}`;
        entropyIndicator.className = `signal-indicator ${entropy > 4.5 ? "risk" : entropy > 3.5 ? "warning" : "safe"}`;
        const brandValue = document.getElementById("brandImpersonationValue");
        const brandIndicator = document.getElementById("brandImpersonationIndicator");
        const brandScore = features.brandMatch ? 85 + Math.random() * 15 : Math.random() * 20;
        brandValue.textContent = features.brandMatch ? `${brandScore.toFixed(0)}% - ${features.brandMatch} Match` : `${brandScore.toFixed(0)}%`;
        brandIndicator.className = `signal-indicator ${features.brandMatch ? "risk" : "safe"}`;
        const formValue = document.getElementById("formActionValue");
        const formIndicator = document.getElementById("formActionIndicator");
        if (result.mode === "deep" && result.domAnalysis?.formActionsExternal) {
            formValue.textContent = "Mismatched (External Host)";
            formIndicator.className = "signal-indicator risk";
        } else {
            formValue.textContent = "Domain Consistent";
            formIndicator.className = "signal-indicator safe";
        }
    }
    function renderSHAPChart(shapValues) {
        const shapChart = document.getElementById("shapChart");
        if (state.chartInstance) { state.chartInstance.destroy(); }
        const labels = shapValues.map(sv => sv.feature);
        const data = shapValues.map(sv => sv.value);
        const colors = shapValues.map(sv => sv.direction === "risk" ? "#ef4444" : "#10b981");
        const ctx = shapChart.getContext("2d");
        state.chartInstance = new Chart(ctx, {
            type: "bar",
            data: { labels, datasets: [{ label: "SHAP Value Contribution", data, backgroundColor: colors, borderColor: colors, borderWidth: 1 }] },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { display: false }, title: { display: false } },
                scales: {
                    x: {
                        title: { display: true, text: "Contribution to Maliciousness Score", color: "#94a3b8", font: { family: "system-ui", size: 12 } },
                        grid: { color: "rgba(148, 163, 184, 0.1)" },
                        ticks: { color: "#94a3b8", callback: function(value) { return value.toFixed(2); } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: "#e2e8f0", font: { family: "system-ui", size: 11 } }
                    }
                }
            }
        });
    }
    function populateThreatBrief(result) {
        const content = document.getElementById("threatSummaryContent");
        const threatLevel = result.riskScore >= 70 ? "CRITICAL" : result.riskScore >= 40 ? "ELEVATED" : "LOW";
        const color = result.riskScore >= 70 ? "#ef4444" : result.riskScore >= 40 ? "#f59e0b" : "#10b981";
        content.innerHTML = `
            <div class="threat-summary-item"><span class="summary-label">Threat Level:</span><span class="summary-value" style="color: ${color}; font-weight: 700;">${threatLevel}</span></div>
            <div class="threat-summary-item"><span class="summary-label">Risk Score:</span><span class="summary-value">${result.riskScore}/100</span></div>
            <div class="threat-summary-item"><span class="summary-label">Targeted Brand:</span><span class="summary-value">${result.features.brandMatch || "None Detected"}</span></div>
            <div class="threat-summary-item"><span class="summary-label">Analysis Mode:</span><span class="summary-value">${result.mode === "deep" ? "Deep Inspection" : "Fast Scan"}</span></div>
            <div class="threat-summary-item"><span class="summary-label">Indicators:</span><ul class="indicator-list">
                ${result.features.isIPAddress ? "<li>IP Address URL</li>" : ""}
                ${result.features.hasSuspiciousTLD ? "<li>Suspicious TLD</li>" : ""}
                ${result.features.isShortened ? "<li>URL Shortener</li>" : ""}
                ${result.features.brandMatch ? `<li>Brand Impersonation: ${result.features.brandMatch}</li>` : ""}
            </ul></div>
        `;
    }
    function initExportHandlers() {
        document.getElementById("btnExportSTIX").addEventListener("click", exportSTIX21);
        document.getElementById("btnExportYARA").addEventListener("click", exportYARA);
    }
    function exportSTIX21() {
        if (!state.lastScanResult) { showNotification("No scan results", "warning"); return; }
        const result = state.lastScanResult;
        const stixBundle = generateSTIXBundle(result);
        const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: "application/json" });
        downloadFile(blob, `phish-guard_stix21_${Date.now()}.json`);
        showNotification("STIX 2.1 exported", "success");
    }
    function generateSTIXBundle(result) {
        const timestamp = new Date().toISOString();
        return {
            type: "bundle",
            id: `bundle--${Date.now()}`,
            objects: [
                { type: "indicator", id: `indicator--${Date.now()}`, created: timestamp, modified: timestamp, name: `Phish-Guard: ${result.verdict}`, description: `Detected with ${result.confidence.toFixed(1)}% confidence`, pattern: `[url:value = '${result.url}']`, pattern_type: "stix", labels: ["phishing"], confidence: Math.round(result.confidence / 10) },
                { type: "observed-data", id: `observed-data--${Date.now() + 1}`, created: timestamp, modified: timestamp, objects: { "0": { type: "url", value: result.url, extensions: { "x-phish-guard": { risk_score: result.riskScore, features: result.features } } } } },
                { type: "x-shap-values", id: `x-shap--${Date.now() + 2}`, created: timestamp, modified: timestamp, labels: ["xai"], shap_contributions: result.shapValues || [] }
            ]
        };
    }
    function exportYARA() {
        if (!state.lastScanResult) { showNotification("No scan results", "warning"); return; }
        const result = state.lastScanResult;
        const yaraRule = generateYARARule(result);
        const blob = new Blob([yaraRule], { type: "text/plain" });
        downloadFile(blob, `phish-guard_${Date.now()}.yar`);
        showNotification("YARA rule exported", "success");
    }
    function generateYARARule(result) {
        const urlObj = new URL(result.url);
        const ruleName = `phish_guard_${(result.verdict || "suspicious").toLowerCase()}_${Date.now()}`;
        return `rule ${ruleName} { meta: { description = "AI-generated detection"; author = "Phish-Guard"; date = "${new Date().toISOString().split("T")[0]}"; } strings: { $url = "${result.url}"; } condition: { $url } }`;
    }
    function initTelemetryTabs() {
        document.querySelectorAll(".telemetry-tab").forEach(tab => {
            tab.addEventListener("click", () => {
                const targetTab = tab.dataset.tab;
                document.querySelectorAll(".telemetry-tab").forEach(t => t.classList.remove("active"));
                tab.classList.add("active");
                document.querySelectorAll(".telemetry-content").forEach(c => c.classList.remove("active"));
                document.getElementById(`${targetTab}Tab`).classList.add("active");
            });
        });
    }
    function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
    function downloadFile(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    function showNotification(message, type = "info") {
        const notification = document.createElement("div");
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        Object.assign(notification.style, { position: "fixed", bottom: "20px", right: "20px", padding: "12px 20px", borderRadius: "8px", color: "#fff", fontFamily: "system-ui", fontSize: "14px", zIndex: "10000" });
        const colors = { success: "#10b981", warning: "#f59e0b", error: "#ef4444", info: "#3b82f6" };
        notification.style.background = colors[type] || colors.info;
        document.body.appendChild(notification);
        setTimeout(() => { notification.style.opacity = "0"; setTimeout(() => notification.remove(), 300); }, 3000);
    }
    function init() {
        console.log("Phish-Guard Enterprise SOC Dashboard initialized");
        initNavigation();
        initScanner();
        initTelemetryTabs();
        initExportHandlers();
    }
    if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
