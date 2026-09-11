/**
 * Phish-Guard - AI-Powered Social Engineering Analyzer
 * ---------------------------------------------------
 * Client-side phishing detection using OpenAI + VirusTotal APIs.
 * BYOK model: API keys stay in browser memory only (never on disk).
 */
(function () {
    'use strict';

    // ================================================================
    //  STATE (keys live here - never in localStorage/disk)
    // ================================================================
    let openaiKey = '';
    let vtKey     = '';

    // ================================================================
    //  DOM REFERENCES
    // ================================================================
    const $ = (sel) => document.querySelector(sel);

    const dom = {
        keyToggle:    $('#keyToggle'),
        keyPanel:     $('#keyPanel'),
        openaiInput:  $('#openaiKey'),
        vtInput:      $('#vtKey'),
        messageInput: $('#messageInput'),
        scanButton:   $('#scanButton'),
        loading:      $('#loading'),
        statusText:   $('#statusText'),
        resultArea:   $('#resultArea'),
    };

    // ================================================================
    //  INIT - wire up event listeners
    // ================================================================
    dom.keyToggle.addEventListener('click', toggleKeyPanel);
    dom.openaiInput.addEventListener('input', (e) => { openaiKey = e.target.value.trim(); });
    dom.vtInput.addEventListener('input',     (e) => { vtKey     = e.target.value.trim(); });
    dom.scanButton.addEventListener('click',  handleScan);

    // Security: wipe keys when the user leaves the page
    window.addEventListener('beforeunload', () => {
        openaiKey = '';
        vtKey     = '';
    });

    // ================================================================
    //  UI HELPERS
    // ================================================================
    function toggleKeyPanel() {
        dom.keyPanel.classList.toggle('collapsed');
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
    }

    function showError(msg) {
        dom.resultArea.innerHTML =
            '<div class="error-box">' + escapeHtml(msg) + '</div>';
    }

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    // ================================================================
    //  MAIN SCAN HANDLER
    // ================================================================
    async function handleScan() {
        const message = dom.messageInput.value.trim();

        if (!message)   return showError('Please paste a suspicious message first.');
        if (!openaiKey) return showError('Please enter your OpenAI API key to enable analysis.');

        setLoading(true);
        clearResults();

        try {
            // 1 - Extract URLs from the message
            setStatus('Extracting URLs from message...');
            const urls = extractURLs(message);

            // 2 - VirusTotal URL scan (requires VT key + at least one URL)
            let vtResults = null;
            if (vtKey && urls.length > 0) {
                setStatus('Scanning URLs via VirusTotal...');
                vtResults = await scanURLsViaVT(urls, vtKey);
            }

            // 3 - OpenAI phishing analysis
            setStatus('Analyzing message with AI...');
            const aiResult = await analyzeWithOpenAI(message, openaiKey);

            // 4 - Render combined results
            setStatus('Analysis complete!');
            renderResults(aiResult, urls, vtResults);
        } catch (err) {
            console.error('Phish-Guard error:', err);
            showError(err.message || 'An unexpected error occurred. Please try again.');
        } finally {
            setLoading(false);
        }
    }

    // ================================================================
    //  URL EXTRACTION
    // ================================================================
    function extractURLs(text) {
        const re  = /https?:\/\/[^\s<>"'`\]\)\u200B]+/gi;
        const raw = text.match(re) || [];
        return [...new Set(raw)];   // de-dupe
    }

    // ================================================================
    //  OPENAI - Phishing Analysis
    // ================================================================
    async function analyzeWithOpenAI(message, apiKey) {
        const systemPrompt = [
            'You are a senior cybersecurity analyst specializing in phishing and social-engineering detection.',
            '',
            'Analyze the user-provided message and return ONLY a JSON object (no markdown fences, no extra text) in this exact shape:',
            '{',
            '  "riskScore": <number 0-100>,',
            '  "verdict": "<safe | suspicious | phishing>",',
            '  "techniques": ["<technique>", ...],',
            '  "summary": "<2-3 sentence plain-English explanation>",',
            '  "recommendations": ["<actionable advice>", ...]',
            '}',
            '',
            'Scoring guide:',
            '  0-25  -> safe',
            '  26-60 -> suspicious',
            '  61-100 -> phishing',
            '',
            'Techniques to detect (pick all that apply):',
            '  urgency, authority, fear, curiosity, financial, impersonation,',
            '  social_proof, scarcity, reciprocity, intimidation',
        ].join('\n');

        const res = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + apiKey,
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                temperature: 0.2,
                max_tokens: 800,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user',   content: 'Analyze this message for phishing:\n\n"""\n' + message + '\n"""' },
                ],
            }),
        });

        if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            if (res.status === 401) throw new Error('Invalid OpenAI API key. Please check and re-enter it.');
            if (res.status === 429) throw new Error('OpenAI rate limit reached. Wait a moment and try again.');
            if (res.status === 402) throw new Error('OpenAI quota exhausted. Check billing at platform.openai.com.');
            throw new Error('OpenAI API error (' + res.status + '): ' + (body.error?.message || 'unknown'));
        }

        const data    = await res.json();
        const raw     = data.choices[0].message.content.trim();
        const cleaned = raw.replace(/```json|```/g, '').trim();

        return JSON.parse(cleaned);
    }
    // ================================================================
    //  VIRUSTOTAL - URL Reputation Scanning via CORS proxy
    // ================================================================
    const VT_CORS_PROXY = 'https://corsproxy.io/?url=';

    async function scanURLsViaVT(urls, apiKey) {
        const results = [];

        for (const url of urls.slice(0, 5)) {   // cap at 5 URLs
            try {
                // Submit the URL for analysis
                const submitRes = await fetch(
                    VT_CORS_PROXY + encodeURIComponent('https://www.virustotal.com/api/v3/urls'),
                    {
                        method: 'POST',
                        headers: {
                            'x-api-key': apiKey,
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({ url: url }),
                    }
                );

                if (!submitRes.ok) {
                    results.push({ url, error: 'Submit failed (' + submitRes.status + ')' });
                    continue;
                }

                const { data } = await submitRes.json();
                const urlId    = data.id;   // base64-encoded URL ID

                // Give VirusTotal time to process
                await sleep(2000);

                // Fetch the analysis results
                const getRes = await fetch(
                    VT_CORS_PROXY + encodeURIComponent('https://www.virustotal.com/api/v3/urls/' + urlId),
                    { headers: { 'x-api-key': apiKey } }
                );

                if (!getRes.ok) {
                    results.push({ url, error: 'Results fetch failed (' + getRes.status + ')' });
                    continue;
                }

                const getResult = await getRes.json();
                const stats     = getResult.data.attributes.last_analysis_stats;

                results.push({
                    url,
                    malicious:  stats.malicious  || 0,
                    suspicious: stats.suspicious || 0,
                    harmless:   stats.harmless   || 0,
                    undetected: stats.undetected || 0,
                    total: Object.values(stats).reduce((a, b) => a + b, 0),
                });
            } catch (e) {
                results.push({ url, error: e.message });
            }
        }

        return results;
    }

    function sleep(ms) {
        return new Promise((r) => setTimeout(r, ms));
    }

    // ================================================================
    //  RENDER RESULTS
    // ================================================================
    function renderResults(ai, urls, vt) {
        const scoreClass   = ai.riskScore <= 25 ? 'low' : ai.riskScore <= 60 ? 'medium' : 'high';
        const verdictLower = (ai.verdict || '').toLowerCase();

        let html = '<div class="result-card">';

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
            html += '<div class="recommendations"><h4>Recommended Actions</h4><ul>';
            ai.recommendations.forEach(function (r) {
                html += '<li>' + escapeHtml(r) + '</li>';
            });
            html += '</ul></div>';
        }

        // ---- Extracted URLs ----
        if (urls.length) {
            html += '<div class="urls-section"><h4>Extracted URLs (' + urls.length + ')</h4>';
            urls.forEach(function (u) {
                html += '<div class="url-item">' + escapeHtml(u) + '</div>';
            });
            html += '</div>';
        }

        // ---- VirusTotal results ----
        if (vt && vt.length) {
            html += '<div class="vt-section"><h4>VirusTotal Scan Results</h4>';
            vt.forEach(function (r) {
                if (r.error) {
                    html += ''
                        + '<div class="vt-url">'
                        +   '<span class="vt-url-text">' + escapeHtml(r.url) + '</span>'
                        +   '<span class="vt-status vt-error">' + escapeHtml(r.error) + '</span>'
                        + '</div>';
                } else {
                    var label, cls;
                    if (r.malicious > 0) {
                        label = r.malicious + ' engine(s) flagged';
                        cls   = 'vt-flagged';
                    } else if (r.suspicious > 0) {
                        label = r.suspicious + ' suspicious';
                        cls   = 'vt-suspicious';
                    } else {
                        label = 'Clean';
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

        html += '</div>';
        dom.resultArea.innerHTML = html;
    }

})();