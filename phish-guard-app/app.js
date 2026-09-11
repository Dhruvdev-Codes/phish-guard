/**
 * Phish-Guard - AI & Heuristic Social Engineering Analyzer
 * ---------------------------------------------------------
 * Client-side phishing detection using OpenAI (GPT-4o-mini) + VirusTotal APIs
 * with built-in Local Heuristic Fallback Engine (Zero-API-Key Mode).
 * BYOK Model: API keys stay in browser memory only.
 */
(function () {
    'use strict';

    // ================================================================
    //  STATE (keys in memory only)
    // ================================================================
    let openaiKey = '';
    let vtKey     = '';
    let lastScanData = null;

    // ================================================================
    //  SAMPLE PRESETS
    // ================================================================
    const SAMPLES = {
        bank: "ALERT from Chase Fraud Dept: A debit card charge of $842.19 at Walmart Online was attempted on your account. If this was NOT you, immediately verify your identity to prevent permanent account suspension: https://chase-security-verify.xyz/login?session=92841",
        ceo: "Hi, I am currently in a board meeting and cannot take calls. I need you to purchase 5x $100 Apple Gift Cards for our client immediately. Scratch the back, take pictures of the pins and reply to this email right away. Please do this discreetly. Thanks, David (CEO)",
        package: "USPS: We tried to deliver your package #US-98218-99, but the address was incomplete. Update your delivery details within 12 hours or item will be returned to sender: http://192.168.1.104/usps-redelivery.php",
        creds: "IT Helpdesk Notice: Your Microsoft 365 password expires in 2 hours. Failure to update credentials will revoke all email and VPN access. Keep same password here: https://login-microsoftonline.account-update.top/auth",
        legit: "Hi team,\n\nJust a quick reminder about our Q3 Project Review tomorrow at 2:00 PM in Conference Room B. Please review the attached slide deck in our shared Google Drive folder prior to the call.\n\nBest regards,\nSarah Jenkins\nProject Lead"
    };

    // ================================================================
    //  DOM REFERENCES
    // ================================================================
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dom = {
        keyToggle:    $('#keyToggle'),
        keyPanel:     $('#keyPanel'),
        openaiInput:  $('#openaiKey'),
        vtInput:      $('#vtKey'),
        messageInput: $('#messageInput'),
        scanButton:   $('#scanButton'),
        clearBtn:     $('#clearBtn'),
        loading:      $('#loading'),
        statusText:   $('#statusText'),
        resultArea:   $('#resultArea'),
        sampleBtns:   $$('.btn-sample'),
    };

    // ================================================================
    //  INIT - Event Listeners
    // ================================================================
    dom.keyToggle.addEventListener('click', toggleKeyPanel);
    dom.openaiInput.addEventListener('input', (e) => { openaiKey = e.target.value.trim(); });
    dom.vtInput.addEventListener('input',     (e) => { vtKey     = e.target.value.trim(); });
    dom.scanButton.addEventListener('click',  handleScan);

    if (dom.clearBtn) {
        dom.clearBtn.addEventListener('click', () => {
            dom.messageInput.value = '';
            clearResults();
            dom.messageInput.focus();
        });
    }

    // Wire sample buttons
    dom.sampleBtns.forEach((btn) => {
        btn.addEventListener('click', () => {
            const key = btn.dataset.sample;
            if (SAMPLES[key]) {
                dom.messageInput.value = SAMPLES[key];
                clearResults();
                dom.messageInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        });
    });

    // Wipe keys on unload
    window.addEventListener('beforeunload', () => {
        openaiKey = '';
        vtKey     = '';
    });

    // ================================================================
    //  UI HELPERS
    // ================================================================
    function toggleKeyPanel() {
        const isCollapsed = dom.keyPanel.classList.toggle('collapsed');
        dom.keyToggle.setAttribute('aria-expanded', !isCollapsed);
    }

    function setLoading(on) {
        dom.scanButton.disabled = on;
        dom.loading.classList.toggle('hidden', !on);
    }

    function setStatus(msg) {
        dom.statusText.textContent = msg;
    }

    function clearResults() {
        dom.resultArea.innerHTML = '';
        lastScanData = null;
    }

    function showError(msg) {
        dom.resultArea.innerHTML =
            '<div class="error-box">' + escapeHtml(msg) + '</div>';
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        const d = document.createElement('div');
        d.textContent = String(str);
        return d.innerHTML;
    }

    // ================================================================
    //  MAIN SCAN HANDLER
    // ================================================================
    async function handleScan() {
        const message = dom.messageInput.value.trim();
        if (!message) return showError('Please paste a message or select a Quick Test Sample above.');

        setLoading(true);
        clearResults();

        try {
            // 1 - Extract URLs
            setStatus('Extracting URLs & network indicators...');
            const urls = extractURLs(message);

            // 2 - VirusTotal Scan (optional)
            let vtResults = null;
            if (vtKey && urls.length > 0) {
                setStatus('Querying VirusTotal threat intelligence...');
                vtResults = await scanURLsWithVirusTotal(urls, vtKey);
            }

            // 3 - Engine Selection: AI vs Heuristic
            let analysis = null;
            let engineUsed = '';

            if (openaiKey) {
                setStatus('Running OpenAI GPT-4o-mini neural analysis...');
                analysis = await analyzeWithOpenAI(message, urls, openaiKey);
                engineUsed = 'AI (GPT-4o-mini)';
            } else {
                setStatus('Running built-in Heuristic Analysis Engine...');
                await new Promise(r => setTimeout(r, 450));
                analysis = analyzeHeuristics(message, urls);
                engineUsed = 'Local Heuristic Engine';
            }

            // 4 - If VirusTotal detected malware, adjust overall score
            if (vtResults && vtResults.some(r => r.malicious > 0)) {
                analysis.riskScore = Math.max(analysis.riskScore, 85);
                analysis.verdict = 'PHISHING';
                if (!analysis.techniques.includes('T1566.002: Malicious URL (VirusTotal Flagged)')) {
                    analysis.techniques.unshift('T1566.002: Malicious URL (VirusTotal Flagged)');
                }
            }

            // 5 - Render UI
            lastScanData = {
                timestamp: new Date().toISOString(),
                engine: engineUsed,
                message: message,
                urls: urls,
                analysis: analysis,
                vtResults: vtResults
            };

            renderResults(analysis, urls, vtResults, engineUsed);

        } catch (err) {
            console.error('Phish-Guard scan error:', err);
            showError(err.message || 'An unexpected error occurred during analysis.');
        } finally {
            setLoading(false);
        }
    }

    // ================================================================
    //  URL EXTRACTION
    // ================================================================
    function extractURLs(text) {
        const urlRegex = /\b(?:https?:\/\/|www\.)[^\s<>"{}|\\^`[\]]+/gi;
        const matches = text.match(urlRegex) || [];
        const normalized = matches.map(u => u.startsWith('http') ? u : 'http://' + u);
        return [...new Set(normalized)];
    }

    // ================================================================
    //  LOCAL HEURISTIC ENGINE (Offline / Fallback)
    // ================================================================
    function analyzeHeuristics(text, urls) {
        const lower = text.toLowerCase();
        let score = 5; // base score
        const techniques = [];
        const detectedCues = [];

        // 1. Urgency & Coercion
        const urgencyPatterns = [
            { rx: /\b(immediately|urgent|within \d+ hours?|right away|act now|suspended|immediate action)\b/i, name: 'Artificial Urgency', weight: 25 },
            { rx: /\b(compromised|unauthorized|fraud|deactivated|permanently closed|revoke|arrest|legal action)\b/i, name: 'Fear & Threat Coercion', weight: 25 },
            { rx: /\b(final notice|last warning|account alert|security alert)\b/i, name: 'High-Priority Alert Simulation', weight: 20 },
        ];
        urgencyPatterns.forEach(p => {
            if (p.rx.test(lower)) {
                score += p.weight;
                techniques.push('Social Engineering: ' + p.name);
                detectedCues.push(p.name);
            }
        });

        // 2. Sensitive Action / Data Requests
        const sensitivePatterns = [
            { rx: /\b(verify your identity|confirm identity|update (your )?(credentials|details|account))\b/i, name: 'T1598: Phishing for Information', weight: 25 },
            { rx: /\b(password|pin code|ssn|social security|credit card|cvv|bank account)\b/i, name: 'T1566: Credential Harvesting', weight: 30 },
            { rx: /\b(gift cards?|apple gift|scratch|wire transfer|western union|bitcoin|crypto)\b/i, name: 'Financial Fraud / Advance Fee Scam', weight: 35 },
            { rx: /\b(board meeting|ceo|executive|discreetly|confidential request)\b/i, name: 'Executive Impersonation (Whaling / BEC)', weight: 25 },
        ];
        sensitivePatterns.forEach(p => {
            if (p.rx.test(lower)) {
                score += p.weight;
                techniques.push(p.name);
                detectedCues.push(p.name);
            }
        });

        // 3. Technical URL Heuristics
        if (urls.length > 0) {
            techniques.push('T1566.002: Embedded External Link');
            urls.forEach(u => {
                try {
                    const parsed = new URL(u);
                    const host = parsed.hostname.toLowerCase();
                    const path = parsed.pathname.toLowerCase();

                    // IP address host
                    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
                        score += 35;
                        techniques.push('Suspicious IP-based URL (' + host + ')');
                    }
                    // Suspicious TLDs
                    if (/\.(xyz|top|tk|ml|ga|cf|gq|click|buzz|club|work|rest|cam|online|site)$/i.test(host)) {
                        score += 25;
                        techniques.push('Abused High-Risk TLD (.' + host.split('.').pop() + ')');
                    }
                    // Deceptive brand in subdomain or path
                    if (/(chase|paypal|microsoft|apple|google|amazon|netflix|usps|fedex|bank|wellsfargo)/i.test(host) &&
                        !/(chase\.com|paypal\.com|microsoft\.com|apple\.com|google\.com|amazon\.com|netflix\.com|usps\.com|fedex\.com)$/i.test(host)) {
                        score += 35;
                        techniques.push('Brand Impersonation in Domain Name (' + host + ')');
                    }
                    // Sensitive paths
                    if (/(login|verify|auth|signin|update|secure|redelivery|session|banking)/i.test(path)) {
                        score += 15;
                        techniques.push('Credential/Verification Endpoint (' + path + ')');
                    }
                } catch (_) {}
            });
        }

        // Clamp score 0 - 100
        score = Math.min(100, Math.max(0, score));

        // Deduplicate techniques
        const uniqueTechniques = [...new Set(techniques)];

        // Verdict & Summary
        let verdict = 'SAFE';
        let summary = '';
        const recommendations = [];

        if (score >= 65) {
            verdict = 'PHISHING';
            summary = `High probability social-engineering attack detected. The message exhibits critical threat indicators including ${detectedCues.join(', ') || 'suspicious language and link attributes'}.`;
            recommendations.push('Do NOT click any embedded links or open attachments.');
            recommendations.push('Do NOT provide passwords, gift card codes, or personal verification data.');
            recommendations.push('Report this communication to your organization’s Information Security / SOC team.');
            recommendations.push('Block the sender address and delete the message.');
        } else if (score >= 30) {
            verdict = 'SUSPICIOUS';
            summary = `Moderate threat indicators identified. The message contains elements often seen in phishing or marketing lures (${detectedCues.join(', ') || 'unverified links'}). Exercise caution.`;
            recommendations.push('Verify the sender via a known trusted out-of-band channel (e.g. phone or internal chat).');
            recommendations.push('Inspect any links without clicking by hovering to verify destination domain.');
            recommendations.push('Do not share sensitive credentials.');
        } else {
            verdict = 'SAFE';
            summary = 'No prominent phishing indicators or malicious patterns detected. The message appears standard and legitimate.';
            recommendations.push('Standard security hygiene: ensure you always verify senders when clicking links.');
        }

        return {
            riskScore: score,
            verdict: verdict,
            techniques: uniqueTechniques.length ? uniqueTechniques : ['Standard Communication'],
            summary: summary,
            recommendations: recommendations
        };
    }

    // ================================================================
    //  OPENAI GPT-4o-mini ANALYSIS ENGINE
    // ================================================================
    async function analyzeWithOpenAI(message, urls, apiKey) {
        const systemPrompt = `You are a Senior Cybersecurity Threat Analyst specializing in Social Engineering, MITRE ATT&CK T1566 (Phishing), and BEC (Business Email Compromise).
Analyze the provided message text and list of extracted URLs.

Respond ONLY with a valid, raw JSON object matching this schema (no markdown fences, no explanatory text outside JSON):
{
  "riskScore": <integer 0 to 100>,
  "verdict": "<SAFE | SUSPICIOUS | PHISHING>",
  "techniques": ["<MITRE ATT&CK or Social Engineering technique tag, e.g. T1566.002: Spearphishing Link, Artificial Urgency, Executive Impersonation, Credential Harvesting>"],
  "summary": "<2-3 sentence concise threat analysis explaining why the message is safe, suspicious, or malicious>",
  "recommendations": ["<Actionable mitigation step 1>", "<Actionable mitigation step 2>", "<Actionable mitigation step 3>"]
}`;

        const userContent = `Message to analyze:\n"""\n${message}\n"""\n\nExtracted URLs found in message:\n${urls.length ? urls.join('\n') : 'None'}`;

        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user',   content: userContent   }
                ],
                temperature: 0.1,
                response_format: { type: 'json_object' }
            })
        });

        if (!resp.ok) {
            let errText = '';
            try {
                const errData = await resp.json();
                errText = errData.error?.message || resp.statusText;
            } catch (_) {
                errText = await resp.text();
            }
            if (resp.status === 401) throw new Error('OpenAI API Key is invalid or expired. Please check your key.');
            if (resp.status === 429) throw new Error('OpenAI Rate limit reached or insufficient quota. Please check your OpenAI account credits.');
            throw new Error(`OpenAI API error (${resp.status}): ${errText}`);
        }

        const data = await resp.json();
        const rawContent = data.choices[0]?.message?.content;
        if (!rawContent) throw new Error('OpenAI returned an empty response.');

        return JSON.parse(rawContent);
    }

    // ================================================================
    //  VIRUSTOTAL URL SCANNING (via CORS proxy)
    // ================================================================
    async function scanURLsWithVirusTotal(urls, apiKey) {
        const results = [];
        const targetURLs = urls.slice(0, 5);

        for (const url of targetURLs) {
            try {
                const urlId = btoa(url).replace(/=/g, '');
                const targetEndpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
                const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(targetEndpoint)}`;

                const resp = await fetch(proxyUrl, {
                    headers: { 'x-apikey': apiKey }
                });

                if (resp.status === 404) {
                    results.push({ url, notFound: true, malicious: 0, suspicious: 0, harmless: 0 });
                    continue;
                }

                if (!resp.ok) {
                    results.push({ url, error: `VT error (${resp.status})` });
                    continue;
                }

                const data = await resp.json();
                const stats = data.data?.attributes?.last_analysis_stats || {};
                results.push({
                    url: url,
                    malicious: stats.malicious || 0,
                    suspicious: stats.suspicious || 0,
                    harmless: stats.harmless || 0,
                    undetected: stats.undetected || 0
                });
            } catch (err) {
                results.push({ url, error: 'Scanning unavailable' });
            }
        }
        return results;
    }

    // ================================================================
    //  RENDER RESULTS
    // ================================================================
    function renderResults(ai, urls, vt, engineName) {
        const scoreClass   = ai.riskScore <= 30 ? 'low' : ai.riskScore <= 64 ? 'medium' : 'high';
        const verdictLower = (ai.verdict || '').toLowerCase();
        const isAi = engineName.includes('GPT');

        let html = '<div class="result-card">';

        // ---- Engine meta pill ----
        html += ''
            + '<div class="result-engine-meta">'
            +   '<span>Analysis Engine</span>'
            +   '<span class="engine-badge ' + (isAi ? 'engine-ai' : 'engine-heuristic') + '">'
            +     (isAi ? '🤖 ' : '⚡ ') + escapeHtml(engineName)
            +   '</span>'
            + '</div>';

        // ---- Risk header: score bar + verdict badge ----
        html += ''
            + '<div class="risk-header">'
            +   '<div class="risk-score-wrapper">'
            +     '<div class="risk-score-bar">'
            +       '<div class="risk-score-fill ' + scoreClass + '" style="width:' + ai.riskScore + '%"></div>'
            +     '</div>'
            +     '<span class="risk-number">' + ai.riskScore + ' / 100</span>'
            +   '</div>'
            +   '<span class="verdict-badge verdict-' + verdictLower + '">' + escapeHtml(ai.verdict) + '</span>'
            + '</div>';

        // ---- Detected techniques ----
        if (ai.techniques && ai.techniques.length) {
            html += '<div class="techniques">';
            ai.techniques.forEach(function (t) {
                html += '<span class="technique-tag">' + escapeHtml(t) + '</span>';
            });
            html += '</div>';
        }

        // ---- Summary ----
        html += '<div class="summary">' + escapeHtml(ai.summary) + '</div>';

        // ---- Recommendations ----
        if (ai.recommendations && ai.recommendations.length) {
            html += '<div class="recommendations"><h4>Recommended Mitigation Steps</h4><ul>';
            ai.recommendations.forEach(function (r) {
                html += '<li>' + escapeHtml(r) + '</li>';
            });
            html += '</ul></div>';
        }

        // ---- Extracted URLs ----
        if (urls && urls.length) {
            html += '<div class="urls-section"><h4>Extracted URLs &amp; Indicators (' + urls.length + ')</h4>';
            urls.forEach(function (u) {
                html += '<div class="url-item">' + escapeHtml(u) + '</div>';
            });
            html += '</div>';
        }

        // ---- VirusTotal results ----
        if (vt && vt.length) {
            html += '<div class="vt-section"><h4>VirusTotal Threat Intel</h4>';
            vt.forEach(function (r) {
                if (r.error) {
                    html += ''
                        + '<div class="vt-url">'
                        +   '<span class="vt-url-text">' + escapeHtml(r.url) + '</span>'
                        +   '<span class="vt-status vt-error">' + escapeHtml(r.error) + '</span>'
                        + '</div>';
                } else if (r.notFound) {
                    html += ''
                        + '<div class="vt-url">'
                        +   '<span class="vt-url-text">' + escapeHtml(r.url) + '</span>'
                        +   '<span class="vt-status vt-suspicious">Unrated / New URL</span>'
                        + '</div>';
                } else {
                    let label, cls;
                    if (r.malicious > 0) {
                        label = '⚠️ ' + r.malicious + ' engines flagged malicious';
                        cls   = 'vt-flagged';
                    } else if (r.suspicious > 0) {
                        label = '⚡ ' + r.suspicious + ' suspicious';
                        cls   = 'vt-suspicious';
                    } else {
                        label = '✓ Clean (0 detections)';
                        cls   = 'vt-clean';
                    }
                    html += ''
                        + '<div class="vt-url">'
                        +   '<span class="vt-url-text">' + escapeHtml(r.url) + '</span>'
                        +   '<span class="vt-status ' + cls + '">' + label + '</span>'
                        + '</div>';
                }
            });
            html += '</div>';
        }

        // ---- Action Bar (Export & Copy Report) ----
        html += ''
            + '<div class="result-actions">'
            +   '<button type="button" class="btn-action" id="copyReportBtn">📋 Copy Incident Report</button>'
            +   '<button type="button" class="btn-action" id="downloadJsonBtn">📥 Download JSON</button>'
            + '</div>';

        html += '</div>';
        dom.resultArea.innerHTML = html;

        // Wire up copy and download
        const copyBtn = document.getElementById('copyReportBtn');
        const jsonBtn = document.getElementById('downloadJsonBtn');

        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                copyMarkdownReport(copyBtn);
            });
        }
        if (jsonBtn) {
            jsonBtn.addEventListener('click', () => {
                downloadJsonReport();
            });
        }
    }

    // ================================================================
    //  EXPORT REPORT HELPERS
    // ================================================================
    function generateMarkdownReport() {
        if (!lastScanData) return '';
        const d = lastScanData;
        let md = `# Phish-Guard Threat Analysis Report\n\n`;
        md += `- **Date/Time:** ${d.timestamp}\n`;
        md += `- **Engine:** ${d.engine}\n`;
        md += `- **Verdict:** ${d.analysis.verdict}\n`;
        md += `- **Risk Score:** ${d.analysis.riskScore} / 100\n\n`;
        md += `## Detected Techniques\n`;
        d.analysis.techniques.forEach(t => { md += `- ${t}\n`; });
        md += `\n## Threat Summary\n${d.analysis.summary}\n\n`;
        md += `## Recommended Actions\n`;
        d.analysis.recommendations.forEach(r => { md += `- ${r}\n`; });
        if (d.urls.length) {
            md += `\n## Extracted URLs\n`;
            d.urls.forEach(u => { md += `- \`${u}\`\n`; });
        }
        if (d.vtResults && d.vtResults.length) {
            md += `\n## VirusTotal Intel\n`;
            d.vtResults.forEach(r => {
                if (r.error) md += `- ${r.url}: Error (${r.error})\n`;
                else md += `- ${r.url}: Malicious: ${r.malicious}, Suspicious: ${r.suspicious}\n`;
            });
        }
        return md;
    }

    function copyMarkdownReport(btn) {
        const md = generateMarkdownReport();
        navigator.clipboard.writeText(md).then(() => {
            const originalText = btn.innerHTML;
            btn.innerHTML = '✅ Copied to Clipboard!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.classList.remove('copied');
            }, 2000);
        }).catch(() => {
            alert('Failed to copy to clipboard.');
        });
    }

    function downloadJsonReport() {
        if (!lastScanData) return;
        const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard-report-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

})();