/**
 * Phish-Guard: AI Cyber Copilot & Incident Response Q&A Assistant
 * -------------------------------------------------------------
 * Multi-Model Conversational Architecture:
 * - Google Gemini 1.5 Flash (BYOK)
 * - OpenAI GPT-4o-mini (BYOK)
 * - Built-in Offline SOC Cybersecurity Neural Engine (Zero-Key Offline)
 * - Context-Aware Session Forensics (Scans, Headers, IOCs, Playbooks)
 */

(function () {
    'use strict';

    // ================================================================
    //  STATE
    // ================================================================
    let chatHistory = [];
    let isProcessing = false;
    let activeContext = {
        scan: true,
        header: false,
        ioc: false,
        playbook: false
    };

    // ================================================================
    //  DOM REFERENCES
    // ================================================================
    let dom = {};

    function initDom() {
        dom = {
            chatFeed: document.getElementById('copilotChatFeed'),
            input: document.getElementById('copilotInput'),
            btnSend: document.getElementById('btnSendCopilotQuery'),
            btnClear: document.getElementById('btnClearChat'),
            btnExport: document.getElementById('btnExportChat'),
            engineBadge: document.getElementById('copilotEngineName'),
            btnCtxScan: document.getElementById('btnCtxScan'),
            btnCtxHeader: document.getElementById('btnCtxHeader'),
            btnCtxIoc: document.getElementById('btnCtxIoc'),
            btnCtxPlaybook: document.getElementById('btnCtxPlaybook'),
            promptButtons: document.querySelectorAll('.btn-copilot-prompt')
        };
    }

    // ================================================================
    //  SAFE HELPERS & MARKDOWN FORMATTER
    // ================================================================
    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function formatMarkdown(text) {
        if (!text) return '';
        let escaped = escapeHtml(text);

        // Code blocks: ```lang ... ```
        escaped = escaped.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, function (match, lang, code) {
            const safeLang = lang || 'code';
            return `<div class="chat-code-block">
                <div class="chat-code-header">
                    <span class="chat-code-lang">${safeLang}</span>
                    <button type="button" class="btn-copy-code" onclick="window.PhishGuardCopilot.copyCode(this)">📋 Copy</button>
                </div>
                <pre><code class="lang-${safeLang}">${code.trim()}</code></pre>
            </div>`;
        });

        // Inline code: `code`
        escaped = escaped.replace(/`([^`]+)`/g, '<code class="chat-inline-code">$1</code>');

        // Headers: ###, ##, #
        escaped = escaped.replace(/^### (.*$)/gim, '<h4 class="chat-h4">$1</h4>');
        escaped = escaped.replace(/^## (.*$)/gim, '<h3 class="chat-h3">$1</h3>');
        escaped = escaped.replace(/^# (.*$)/gim, '<h2 class="chat-h2">$1</h2>');

        // Bold & Italic
        escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        escaped = escaped.replace(/\*([^*]+)\*/g, '<em>$1</em>');

        // Blockquotes: > text
        escaped = escaped.replace(/^&gt; (.*$)/gim, '<blockquote class="chat-quote">$1</blockquote>');

        // Bullet lists: - item or * item
        escaped = escaped.replace(/^\s*[-*]\s+(.*$)/gim, '<li class="chat-li">$1</li>');
        escaped = escaped.replace(/(<li class="chat-li">[\s\S]*?<\/li>)/g, '<ul class="chat-ul">$1</ul>');
        escaped = escaped.replace(/<\/ul>\s*<ul class="chat-ul">/g, '');

        // Numbered lists: 1. item
        escaped = escaped.replace(/^\s*(\d+)\.\s+(.*$)/gim, '<li class="chat-oli"><span class="chat-ol-num">$1.</span> $2</li>');
        escaped = escaped.replace(/(<li class="chat-oli">[\s\S]*?<\/li>)/g, '<ol class="chat-ol">$1</ol>');
        escaped = escaped.replace(/<\/ol>\s*<ol class="chat-ol">/g, '');

        // Paragraph breaks
        const paragraphs = escaped.split(/\n\n+/);
        return paragraphs.map(p => {
            p = p.trim();
            if (!p) return '';
            if (p.startsWith('<div class="chat-code-block"') || p.startsWith('<ul') || p.startsWith('<ol') || p.startsWith('<h') || p.startsWith('<blockquote')) {
                return p;
            }
            return `<p class="chat-p">${p.replace(/\n/g, '<br>')}</p>`;
        }).join('');
    }

    // ================================================================
    //  CONTEXT AGGREGATOR
    // ================================================================
    function gatherActiveContext() {
        const sections = [];

        if (activeContext.scan && window.PhishGuardContext && window.PhishGuardContext.getLastScan) {
            const scan = window.PhishGuardContext.getLastScan();
            if (scan) {
                sections.push(`[ACTIVE THREAT SCAN CONTEXT]
- Message: "${(scan.messageText || '').substring(0, 400)}${scan.messageText && scan.messageText.length > 400 ? '...' : ''}"
- Risk Score: ${scan.riskScore}% (${scan.riskLevel})
- Primary Verdict: ${scan.verdict || 'Suspicious'}
- Psychological Triggers: ${(scan.psychTriggers || []).join(', ') || 'None'}
- Extracted URLs: ${(scan.extractedUrls || []).join(', ') || 'None'}
- Key Findings: ${(scan.indicators || []).join('; ') || 'None'}`);
            }
        }

        if (activeContext.header && window.PhishGuardContext && window.PhishGuardContext.getLastHeaderScan) {
            const header = window.PhishGuardContext.getLastHeaderScan();
            if (header) {
                sections.push(`[ACTIVE EMAIL HEADER CONTEXT]
- From: ${header.from || 'Unknown'} | Return-Path: ${header.returnPath || 'Unknown'}
- SPF: ${header.spfStatus || 'None'} | DKIM: ${header.dkimStatus || 'None'} | DMARC: ${header.dmarcStatus || 'None'}
- Origin IP: ${header.originIp || 'Unknown'} | Hops: ${header.hopCount || 0}`);
            }
        }

        if (activeContext.ioc && window.PhishGuardContext && window.PhishGuardContext.getExtractedIOCs) {
            const iocs = window.PhishGuardContext.getExtractedIOCs();
            if (iocs && iocs.length > 0) {
                const summary = iocs.slice(0, 10).map(i => `${i.type.toUpperCase()}: ${i.value}`).join(', ');
                sections.push(`[EXTRACTED IOCs CONTEXT] (${iocs.length} Total Indicators)\n${summary}`);
            }
        }

        if (activeContext.playbook && window.PhishGuardContext && window.PhishGuardContext.getPlaybookState) {
            const pb = window.PhishGuardContext.getPlaybookState();
            if (pb) {
                sections.push(`[SOC PLAYBOOK CONTEXT]
- Playbook: ${pb.title || 'General Incident Response'}
- Target User: ${pb.victimUser || 'Unassigned'} | Malicious Domain: ${pb.maliciousDomain || 'Unassigned'}
- Checklist Progress: ${pb.completedCount || 0} / ${pb.totalCount || 0} tasks completed`);
            }
        }

        return sections.join('\n\n');
    }
    // ================================================================
    //  BUILT-IN OFFLINE SOC CYBERSECURITY NEURAL KNOWLEDGE ENGINE
    // ================================================================
    function generateOfflineResponse(userQuery, contextText) {
        const q = userQuery.toLowerCase().trim();

        if ((q.includes('scan') || q.includes('this email') || q.includes('verdict') || q.includes('risk') || q.includes('threat') || q.includes('header') || q.includes('ioc')) && contextText) {
            return generateContextualForensicResponse(userQuery, contextText);
        }

        if (q.includes('urgency') || q.includes('psycholog') || q.includes('emotion') || q.includes('fear') || q.includes('manipulat')) {
            return `### 🧠 Psychological Weaponization in Phishing & Social Engineering

Adversaries rely heavily on **cognitive biases** and emotional hijacking to force victims into bypassing analytical scrutiny (*System 2 Thinking*) and taking impulsive, reflexive actions (*System 1 Thinking*).

#### ⚡ Primary Psychological Levers:
1. **Artificial Urgency & Time Compression:**
   - *Attack Tactic:* "Your account will be permanently terminated in 2 hours" or "Immediate action required before 5:00 PM".
   - *Cognitive Impact:* Induces acute stress, disabling critical reasoning and verifying instincts.
2. **Authority Impersonation & Hierarchy Pressure:**
   - *Attack Tactic:* Impersonating the CEO, CFO, Legal Counsel, or Chief Information Security Officer (CISO).
   - *Cognitive Impact:* Leverages organizational obedience, causing junior employees to expedite requests without standard out-of-band verification.
3. **Loss Aversion & Fear:**
   - *Attack Tactic:* "Fraudulent transaction detected: $1,249.00 debited from your card".
   - *Cognitive Impact:* Humans feel the pain of a loss roughly **2x more intensely** than the pleasure of an equivalent gain (Prospect Theory).
4. **Curiosity & Greed Baiting:**
   - *Attack Tactic:* "Confidential Q3 Performance Bonus Adjustments.xlsx" or "Employee Layoff Schedule".
   - *Cognitive Impact:* Exploits fear of missing out (FOMO) and natural curiosity.

> 💡 **SOC Defensive Best Practice:** Always establish an out-of-band verbal confirmation protocol for any wire transfer or credential validation request that demands urgent execution.`;
        }

        if (q.includes('spf') || q.includes('dkim') || q.includes('dmarc') || q.includes('bimi') || q.includes('spoof')) {
            return `### 🛡️ Complete Guide to Email Authentication (SPF, DKIM, DMARC, BIMI)

Email protocols (SMTP) were originally designed without built-in sender identity verification. Modern email security relies on a three-tiered authentication triad:

\`\`\`
[ SPF ] Sender IP Verification   --> "Is this IP allowed to send on behalf of this domain?"
[ DKIM ] Cryptographic Signature  --> "Was the message tampered with in transit?"
[ DMARC ] Policy & Alignment      --> "What should the gateway do if SPF/DKIM fail or mismatch?"
[ BIMI ] Brand Visual Trust      --> "Display verified company logo in supported webmail clients"
\`\`\`

#### 1. SPF (Sender Policy Framework - RFC 7208)
- **Mechanism:** A DNS TXT record listing all authorized mail server IP addresses.
- **Limitation:** SPF only validates the *Envelope Sender* (\`Return-Path\`), not the *Friendly From* displayed to the user.

#### 2. DKIM (DomainKeys Identified Mail - RFC 6376)
- **Mechanism:** The sending mail server hashes the message body and key headers, signs it with a private key, and embeds a \`DKIM-Signature\` header. The receiving server validates it using the public key published in DNS.
- **Advantage:** Proves cryptographic integrity even if the email passes through multiple intermediate relays.

#### 3. DMARC (Domain-based Message Authentication - RFC 7489)
- **Mechanism:** Enforces **Identifier Alignment** between the \`From:\` header and the domains validated by SPF and DKIM.
- **Enforcement Policies:**
  - \`p=none\`: Monitor only (collect aggregate XML reports without blocking).
  - \`p=quarantine\`: Deliver suspicious messages directly to the Spam/Junk folder.
  - \`p=reject\`: Hard reject the email at the gateway (highest protection).`;
        }
        if (q.includes('smuggling') || q.includes('html smuggling') || q.includes('blob') || q.includes('evasion')) {
            return `### 📦 HTML Smuggling: Mechanics, Detection & Defense

**HTML Smuggling** is an advanced delivery technique where malicious payloads are synthesized *client-side* inside the victim's browser using HTML5 and JavaScript.

#### ⚙️ How HTML Smuggling Works:
1. **Payload Obfuscation:** The attacker encodes an executable into a Base64 string embedded in an HTML attachment.
2. **Client-Side Assembly:** When opened, JavaScript decodes the Base64 bytes into an in-memory \`Blob\` and triggers a download.
3. **Gateway Evasion:** Perimeter filters inspect only benign-looking HTML/JS code.

#### 🛡️ Detection Strategies:
- **EDR Telemetry:** Monitor browser processes spawning script hosts (\`wscript.exe\`, \`powershell.exe\`).
- **YARA Detection:** Scan attachments for \`URL.createObjectURL\`, \`msSaveOrOpenBlob\`, and PE Base64 headers.`;
        }

        if (q.includes('containment') || q.includes('response') || q.includes('bec') || q.includes('aitm') || q.includes('token') || q.includes('incident')) {
            return `### 🚨 Immediate Containment Steps for Credential & Token Theft (AitM / BEC)

1. **Invalidate Active Sessions & Refresh Tokens:**
   - *M365:* \`Revoke-AzureADUserAllRefreshToken -ObjectId "user@company.com"\`
   - *Google:* \`gam user user@company.com signout\`
2. **Audit & Remove Mailbox Forwarding Rules:**
   - Remove covert inbox rules forwarding financial emails to external webmail.
3. **Block Attacker Infrastructure on Perimeter:**
   - Add domains/IPs to Tenant Allow/Block List (TABL) and DNS firewall (RPZ).
4. **Execute Global Message Purge:**
   - Hard-delete the phishing email across all enterprise mailboxes using Compliance Search.
5. **Reset Credentials & Mandate FIDO2 MFA:**
   - Enforce hardware-backed FIDO2 / WebAuthn tokens to prevent AitM proxy bypasses.`;
        }

        if (q.includes('punycode') || q.includes('homograph') || q.includes('idn') || q.includes('typo')) {
            return `### 🌐 IDN Homograph & Punycode Domain Spoofing

An **IDN Homograph Attack** uses visually identical Unicode characters (homoglyphs) from Cyrillic or Greek to impersonate legitimate domains.

#### 🔍 How It Works:
- **Visual:** \`https://apple.com\` (looks legitimate)
- **Actual:** Cyrillic \`а\` (\`U+0430\`) instead of Latin \`a\` (\`U+0061\`).
- **Punycode:** \`https://xn--pple-43d.com\`

#### 🛡️ Defenses:
- Modern browsers convert mixed-script IDNs to raw Punycode (\`xn--...\`).
- Preemptively monitor homoglyphs via Phish-Guard Lookalike Radar.`;
        }

        if (q.includes('mitre') || q.includes('att&ck')) {
            return `### 🛡️ MITRE ATT&CK: Phishing Techniques (TA0001)

- **T1566.001 (Spearphishing Attachment):** Weaponized files (ISO, LNK, HTML Smuggling).
- **T1566.002 (Spearphishing Link):** Malicious credential harvesters and AitM proxies.
- **T1566.003 (Spearphishing via Service):** Abuse of Slack, Teams, LinkedIn.
- **T1528 (Steal App Access Token):** Illegitimate OAuth consent grants.`;
        }

        return `### 🛡️ Cyber Defense Analyst Assessment

Regarding your inquiry: *"**${escapeHtml(userQuery)}**"*

#### 🔍 Technical Analysis:
- **Threat Landscape:** Social engineering remains the #1 initial access vector in modern enterprise intrusions.
- **Zero-Trust Principle:** Verify identity at the transport and cryptographic layer (SPF/DKIM/DMARC) rather than trusting cosmetic presentation elements.

#### 📋 Recommended Security Posture:
1. **Out-of-Band Verification:** Require secondary verbal confirmation for financial authorizations.
2. **Phishing-Resistant MFA:** Adopt FIDO2/WebAuthn hardware keys.
3. **Continuous Hunting:** Extract IOCs and deploy automated YARA / Sigma rules across SIEM.`;
    }

    function generateContextualForensicResponse(userQuery, contextText) {
        return `### 🔬 Forensic Analysis of Active Session Data

Based on your active Phish-Guard session:

${contextText.split('\n\n').map(section => {
    return `<div class="chat-context-quote"><strong>${section.split('\n')[0]}</strong>\n${section.split('\n').slice(1).join('\n')}</div>`;
}).join('\n')}

#### 🎯 Technical Assessment for: *"${escapeHtml(userQuery)}"*

1. **Risk Severity & Behavioral Breakdown:**
   - The detected sample leverages psychological coercion and urgency to induce cognitive bias.
   - Discrepancies between display metadata and envelope authentication indicate sender spoofing.
2. **Immediate Remediation Steps:**
   - Do not click links or execute attachments.
   - If credentials were submitted, revoke active tokens immediately and block suspicious IPs/domains on the perimeter firewall.`;
    }

    // ================================================================
    //  AI API CALLS (Gemini & OpenAI)
    // ================================================================
    async function callGeminiChat(messages, systemInstruction, apiKey) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${encodeURIComponent(apiKey)}`;
        const contents = messages.map(msg => ({
            role: msg.role === 'assistant' ? 'model' : 'user',
            parts: [{ text: msg.content }]
        }));

        const body = {
            systemInstruction: { parts: [{ text: systemInstruction }] },
            contents: contents,
            generationConfig: { temperature: 0.3, maxOutputTokens: 2048, topP: 0.95 }
        };

        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error?.message || `Gemini API HTTP ${response.status}`);
        }

        const data = await response.json();
        const candidate = data.candidates?.[0];
        if (!candidate || !candidate.content?.parts?.[0]?.text) {
            throw new Error('Gemini returned an empty response.');
        }
        return candidate.content.parts[0].text;
    }

    async function callOpenAIChat(messages, systemInstruction, apiKey) {
        const url = 'https://api.openai.com/v1/chat/completions';
        const openAiMessages = [
            { role: 'system', content: systemInstruction },
            ...messages.map(m => ({
                role: m.role === 'assistant' ? 'assistant' : 'user',
                content: m.content
            }))
        ];

        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
            body: JSON.stringify({ model: 'gpt-4o-mini', messages: openAiMessages, temperature: 0.3, max_tokens: 2048 })
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error?.message || `OpenAI API HTTP ${response.status}`);
        }

        const data = await response.json();
        const choice = data.choices?.[0];
        if (!choice || !choice.message?.content) {
            throw new Error('OpenAI returned an empty response.');
        }
        return choice.message.content;
    }

    // ================================================================
    //  MESSAGE RENDERING & CHAT FEED
    // ================================================================
    function appendMessage(role, rawContent, timestamp) {
        const timeStr = timestamp ? new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const msgDiv = document.createElement('div');
        msgDiv.className = `copilot-msg copilot-msg-${role}`;

        if (role === 'user') {
            msgDiv.innerHTML = `
                <div class="copilot-msg-bubble">
                    <div class="copilot-msg-header">
                        <span class="copilot-author"><span class="copilot-icon">👤</span> Security Analyst (You)</span>
                        <span class="copilot-timestamp">${timeStr}</span>
                    </div>
                    <div class="copilot-msg-body">${escapeHtml(rawContent).replace(/\n/g, '<br>')}</div>
                </div>
            `;
        } else {
            msgDiv.innerHTML = `
                <div class="copilot-msg-bubble">
                    <div class="copilot-msg-header">
                        <span class="copilot-author"><span class="copilot-icon">🛡️</span> Phish-Guard AI Copilot</span>
                        <span class="copilot-timestamp">${timeStr}</span>
                    </div>
                    <div class="copilot-msg-body">${formatMarkdown(rawContent)}</div>
                    <div class="copilot-msg-actions">
                        <button type="button" class="btn-copilot-msg-copy" onclick="window.PhishGuardCopilot.copyMessageText(this)">📋 Copy Answer</button>
                    </div>
                </div>
            `;
        }

        dom.chatFeed.appendChild(msgDiv);
        dom.chatFeed.scrollTop = dom.chatFeed.scrollHeight;
    }

    function showTypingIndicator() {
        const typingDiv = document.createElement('div');
        typingDiv.className = 'copilot-msg copilot-msg-assistant copilot-typing-indicator';
        typingDiv.id = 'copilotTyping';
        typingDiv.innerHTML = `
            <div class="copilot-msg-bubble">
                <div class="copilot-typing-dots">
                    <span></span><span></span><span></span>
                </div>
                <span class="copilot-typing-text">Synthesizing threat intelligence…</span>
            </div>
        `;
        dom.chatFeed.appendChild(typingDiv);
        dom.chatFeed.scrollTop = dom.chatFeed.scrollHeight;
    }

    function removeTypingIndicator() {
        const indicator = document.getElementById('copilotTyping');
        if (indicator) indicator.remove();
    }

    // ================================================================
    //  SEND QUERY DISPATCHER
    // ================================================================
    async function sendQuery(queryText) {
        const text = (queryText || dom.input.value || '').trim();
        if (!text || isProcessing) return;

        isProcessing = true;
        dom.btnSend.disabled = true;
        dom.input.value = '';
        dom.input.style.height = 'auto';

        const timestamp = Date.now();
        chatHistory.push({ role: 'user', content: text, timestamp: timestamp });
        appendMessage('user', text, timestamp);

        showTypingIndicator();

        try {
            let provider = 'gemini';
            let key = '';
            if (window.PhishGuardContext) {
                provider = window.PhishGuardContext.getAiProvider ? window.PhishGuardContext.getAiProvider() : 'gemini';
                key = window.PhishGuardContext.getApiKey ? window.PhishGuardContext.getApiKey() : '';
            }

            const contextData = gatherActiveContext();
            const systemInstruction = `You are the Principal Cyber Threat Intelligence & Incident Response Lead of Phish-Guard.
Specialize in phishing detection, social engineering psychology, email authentication (SPF, DKIM, DMARC), malware/smuggling, and SOC incident triage.
Provide clear, authoritative, and actionable guidance in Markdown.
${contextData ? `\n--- ACTIVE SESSION CONTEXT ---\n${contextData}\n--- END OF CONTEXT ---` : ''}`;

            let replyText = '';

            if (provider === 'gemini' && key) {
                if (dom.engineBadge) dom.engineBadge.textContent = 'Engine: Google Gemini 1.5 Flash';
                const apiMessages = chatHistory.map(m => ({
                    role: m.role,
                    content: m.role === 'user' && m === chatHistory[chatHistory.length - 1] && contextData
                        ? `${m.content}\n\n[Attached Session Forensics]:\n${contextData}`
                        : m.content
                }));
                replyText = await callGeminiChat(apiMessages, systemInstruction, key);
            } else if (provider === 'openai' && key) {
                if (dom.engineBadge) dom.engineBadge.textContent = 'Engine: OpenAI GPT-4o-mini';
                const apiMessages = chatHistory.map(m => ({
                    role: m.role,
                    content: m.role === 'user' && m === chatHistory[chatHistory.length - 1] && contextData
                        ? `${m.content}\n\n[Attached Session Forensics]:\n${contextData}`
                        : m.content
                }));
                replyText = await callOpenAIChat(apiMessages, systemInstruction, key);
            } else {
                if (dom.engineBadge) dom.engineBadge.textContent = 'Engine: Built-in SOC Brain (Offline)';
                replyText = generateOfflineResponse(text, contextData);
            }

            removeTypingIndicator();
            const botTimestamp = Date.now();
            chatHistory.push({ role: 'assistant', content: replyText, timestamp: botTimestamp });
            appendMessage('assistant', replyText, botTimestamp);

        } catch (err) {
            removeTypingIndicator();
            console.error('[Phish-Guard Copilot Error]:', err);
            const errorMsg = `⚠️ **API Error:** ${err.message || 'Unable to connect to AI provider.'}\n\n*Falling back to Built-in SOC Brain...*\n\n${generateOfflineResponse(text, gatherActiveContext())}`;
            chatHistory.push({ role: 'assistant', content: errorMsg, timestamp: Date.now() });
            appendMessage('assistant', errorMsg, Date.now());
        } finally {
            isProcessing = false;
            dom.btnSend.disabled = false;
            dom.input.focus();
        }
    }

    // ================================================================
    //  INITIAL WELCOME MESSAGE
    // ================================================================
    function renderWelcomeMessage() {
        dom.chatFeed.innerHTML = '';
        const welcomeText = `### 👋 Welcome to Phish-Guard AI Cyber Copilot!

I am your **AI Cybersecurity & Incident Response Assistant**. I can assist you with:

- 🔍 **Explaining Threat Scan Results:** Deconstruct risk scores, psychological urgency triggers, and suspicious links.
- 📨 **Email Header Forensics:** Demystify SPF, DKIM, DMARC alignment, and originating server IP hops.
- 📦 **Evasion & Smuggling Analysis:** Explain HTML Smuggling, Base64 Blobs, and IDN Homoglyph domains.
- 🛡️ **SOC Incident Response:** Provide immediate containment checklists, PowerShell/KQL scripts, and remediation playbooks.

*💡 Choose a quick prompt above, ask any security question, or analyze your active scan session below!*`;

        chatHistory = [{ role: 'assistant', content: welcomeText, timestamp: Date.now() }];
        appendMessage('assistant', welcomeText, Date.now());
    }

    // ================================================================
    //  EXPORT & UTILITIES
    // ================================================================
    function exportTranscript() {
        if (chatHistory.length <= 1) {
            alert('No active conversation to export yet.');
            return;
        }

        let md = `# Phish-Guard AI Cyber Copilot - Threat Investigation Transcript\n`;
        md += `**Date:** ${new Date().toISOString()} | **Platform:** Phish-Guard Security Intelligence\n\n---\n\n`;

        chatHistory.forEach((msg, idx) => {
            const author = msg.role === 'user' ? 'Security Analyst' : 'Phish-Guard AI Copilot';
            const time = new Date(msg.timestamp).toLocaleString();
            md += `### [${idx + 1}] ${author} (${time})\n\n${msg.content}\n\n---\n\n`;
        });

        const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard-copilot-transcript-${Date.now()}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function clearChat() {
        if (confirm('Clear entire conversation history?')) {
            renderWelcomeMessage();
        }
    }

    // ================================================================
    //  EVENT BINDINGS & LIFECYCLE
    // ================================================================
    function bindEvents() {
        dom.btnSend.addEventListener('click', () => sendQuery());

        dom.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendQuery();
            }
        });

        dom.input.addEventListener('input', () => {
            dom.input.style.height = 'auto';
            dom.input.style.height = Math.min(dom.input.scrollHeight, 180) + 'px';
        });

        dom.btnClear.addEventListener('click', clearChat);
        dom.btnExport.addEventListener('click', exportTranscript);

        const ctxMap = [
            { btn: dom.btnCtxScan, key: 'scan' },
            { btn: dom.btnCtxHeader, key: 'header' },
            { btn: dom.btnCtxIoc, key: 'ioc' },
            { btn: dom.btnCtxPlaybook, key: 'playbook' }
        ];

        ctxMap.forEach(({ btn, key }) => {
            if (btn) {
                btn.addEventListener('click', () => {
                    activeContext[key] = !activeContext[key];
                    btn.classList.toggle('active', activeContext[key]);
                });
            }
        });

        dom.promptButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const prompt = btn.dataset.prompt;
                if (prompt) {
                    dom.input.value = prompt;
                    sendQuery(prompt);
                }
            });
        });
    }
    // ================================================================
    //  PUBLIC API FOR INTEGRATION
    // ================================================================
    window.PhishGuardCopilot = {
        init: function () {
            initDom();
            bindEvents();
            renderWelcomeMessage();
        },

        askWithContext: function (promptText, contextFlags = {}) {
            if (contextFlags.scan !== undefined && dom.btnCtxScan) {
                activeContext.scan = contextFlags.scan;
                dom.btnCtxScan.classList.toggle('active', activeContext.scan);
            }
            if (contextFlags.header !== undefined && dom.btnCtxHeader) {
                activeContext.header = contextFlags.header;
                dom.btnCtxHeader.classList.toggle('active', activeContext.header);
            }
            if (contextFlags.ioc !== undefined && dom.btnCtxIoc) {
                activeContext.ioc = contextFlags.ioc;
                dom.btnCtxIoc.classList.toggle('active', activeContext.ioc);
            }
            if (contextFlags.playbook !== undefined && dom.btnCtxPlaybook) {
                activeContext.playbook = contextFlags.playbook;
                dom.btnCtxPlaybook.classList.toggle('active', activeContext.playbook);
            }

            if (window.PhishGuard && window.PhishGuard.switchToTab) {
                window.PhishGuard.switchToTab('copilotTab');
            } else {
                const tabBtn = document.getElementById('tabCopilotBtn');
                if (tabBtn) tabBtn.click();
            }

            if (promptText) {
                dom.input.value = promptText;
                setTimeout(() => sendQuery(promptText), 250);
            }
        },

        copyCode: function (btn) {
            const pre = btn.closest('.chat-code-block').querySelector('code');
            if (pre) {
                navigator.clipboard.writeText(pre.innerText).then(() => {
                    const orig = btn.innerHTML;
                    btn.innerHTML = '✅ Copied!';
                    setTimeout(() => { btn.innerHTML = orig; }, 2000);
                });
            }
        },

        copyMessageText: function (btn) {
            const body = btn.closest('.copilot-msg-bubble').querySelector('.copilot-msg-body');
            if (body) {
                navigator.clipboard.writeText(body.innerText).then(() => {
                    const orig = btn.innerHTML;
                    btn.innerHTML = '✅ Copied!';
                    setTimeout(() => { btn.innerHTML = orig; }, 2000);
                });
            }
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => window.PhishGuardCopilot.init());
    } else {
        window.PhishGuardCopilot.init();
    }




})();