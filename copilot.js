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
    let deliberateOfflineChoice = false;
    let pendingPromptOnSetup = null;
    let activeContext = {
        scan: true,
        header: true,
        ioc: true,
        playbook: true
    };

    // ================================================================
    //  DOM REFERENCES
    // ================================================================
    let dom = {};

    function initDom() {
        dom = {
            chatFeed: document.getElementById('copilotChatFeed'),
            input: document.getElementById('copilotInput'),
            btnSend: document.getElementById('btnCopilotSend') || document.getElementById('btnSendCopilotQuery'),
            btnClear: document.getElementById('btnCopilotClear') || document.getElementById('btnClearChat'),
            btnExport: document.getElementById('btnCopilotExport') || document.getElementById('btnExportChat'),
            engineBadge: document.getElementById('copilotEngineBadge') || document.getElementById('copilotEngineName'),
            engineIndicator: document.getElementById('copilotEngineIndicator'),
            btnConfig: document.getElementById('btnCopilotConfig'),
            btnCtxScan: document.getElementById('btnCtxScan'),
            btnCtxHeader: document.getElementById('btnCtxHeader'),
            btnCtxIoc: document.getElementById('btnCtxIoc'),
            btnCtxPlaybook: document.getElementById('btnCtxPlaybook'),
            promptButtons: document.querySelectorAll('.btn-copilot-prompt'),
            // Modal elements
            modalOverlay: document.getElementById('copilotSetupModal'),
            modalClose: document.getElementById('copilotModalClose'),
            modalForm: document.getElementById('copilotSetupForm'),
            modalProvider: document.getElementById('copilotModalProvider'),
            modalApiKey: document.getElementById('copilotModalApiKey'),
            modalKeyToggle: document.getElementById('copilotModalKeyToggle'),
            modalKeyLabel: document.getElementById('copilotModalKeyLabel'),
            modalKeyHint: document.getElementById('copilotModalKeyHint'),
            modalModel: document.getElementById('copilotModalModel'),
            modalError: document.getElementById('copilotModalError'),
            modalSaveBtn: document.getElementById('copilotModalSaveBtn'),
            modalSkipBtn: document.getElementById('copilotModalSkipBtn')
        };
    }

    // ================================================================
    //  UPDATED PRODUCTION-GRADE SYSTEM PROMPT
    // ================================================================
    const UPDATED_SOC_SYSTEM_PROMPT = `You are Phish-Guard AI Copilot, an advanced, interactive, and conversational AI security intelligence assistant designed for Security Operations Center (SOC) analysts.

### Personality & Tone
- **Natural & Conversational:** Speak fluently, clearly, and engagingly like ChatGPT or Gemini. Avoid forcing every single response into a rigid incident-report template unless a genuine security threat, phishing artifact, or IoC analysis is actually being requested.
- **Adaptive Capabilities:**
  1. **General & System Inquiries:** If asked about yourself, your underlying model, capabilities, or general concepts, answer directly, transparently, and conversationally.
  2. **Casual Chat & Greetings:** Respond to greetings warmly and professionally as an expert SOC partner.
  3. **Threat Intelligence & Incident Response:** When analyzing phishing emails, headers, malicious URLs, or security logs, provide structured, highly rigorous technical analysis (Threat Landscape, Zero-Trust Principles, YARA/Sigma rule recommendations, and mitigation steps).
- **Dynamic Formatting:** Use markdown headers and bullet points only when delivering technical security assessments or incident investigations, rather than applying a blanket template to unrelated chats.`;

    // ================================================================
    //  INTENT CLASSIFIER & ROUTER
    // ================================================================
    function classifyUserIntent(userMessage) {
        if (!userMessage) return 'GENERAL_INQUIRY';
        const q = userMessage.trim().toLowerCase();

        // 1. GREETING
        const greetingPatterns = [
            /^(hi|hello|hey|greetings|howdy|sup|good morning|good afternoon|good evening|yo)\b/i,
            /^(hi|hello|hey)\s+there/i
        ];
        if (greetingPatterns.some(rx => rx.test(q)) && q.split(/\s+/).length <= 4) {
            return 'GREETING';
        }

        // 2. THANKS / AFFIRMATION
        if (/^(thanks|thank you|thx|awesome|cool|great|ok|okay|got it|perfect|cheers|nice)\b/i.test(q) && q.split(/\s+/).length <= 5) {
            return 'CASUAL_THANKS';
        }

        // 3. META / ARCHITECTURE / IDENTITY INQUIRY
        const metaPatterns = [
            /\b(what|which)\s+(ai\s+)?(model|engine|llm|version)\b/i,
            /\b(who\s+are\s+you|what\s+are\s+you|what\s+can\s+you\s+do|tell\s+me\s+about\s+yourself)\b/i,
            /\b(how\s+do\s+you\s+work|how\s+does\s+this\s+work|what\s+is\s+phish-guard|what\s+is\s+this\s+tool)\b/i
        ];
        if (metaPatterns.some(rx => rx.test(q))) {
            return 'META_INQUIRY';
        }

        // 4. THREAT ANALYSIS & FORENSICS
        const threatKeywords = [
            'phish', 'spf', 'dkim', 'dmarc', 'bimi', 'header', 'spoof', 'url', 'domain', 'ip',
            'smuggl', 'payload', 'ioc', 'yara', 'sigma', 'kql', 'splunk', 'quishing', 'qr',
            'homograph', 'punycode', 'typo', 'attack', 'malware', 'soc', 'triage', 'incident',
            'containment', 'aitm', 'token', 'bec', 'cve', 'mitre', 'vulnerability', 'firewall',
            'siem', 'edr', 'powershell', 'ransomware', 'credential', 'whaling', 'spear',
            'psychology', 'bias', 'urgency', 'authority', 'reverse engineer'
        ];
        if (threatKeywords.some(kw => q.includes(kw))) {
            return 'THREAT_ANALYSIS';
        }

        return 'GENERAL_INQUIRY';
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
        // Normalize newlines
        let normalized = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n');

        // 1. Extract Code Blocks before HTML escaping to preserve code formatting
        const codeBlocks = [];
        normalized = normalized.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, function (match, lang, code) {
            const safeLang = lang || 'code';
            const placeholder = `__PHISH_CODE_BLOCK_${codeBlocks.length}__`;
            codeBlocks.push(`<div class="chat-code-block">
                <div class="chat-code-header">
                    <span class="chat-code-lang">${escapeHtml(safeLang)}</span>
                    <button type="button" class="btn-copy-code" onclick="window.PhishGuardCopilot.copyCode(this)">📋 Copy</button>
                </div>
                <pre><code class="lang-${escapeHtml(safeLang)}">${escapeHtml(code.trim())}</code></pre>
            </div>`);
            return placeholder;
        });

        // 2. Escape HTML for the rest of the text
        let escaped = escapeHtml(normalized);

        // 3. Inline code: `code`
        escaped = escaped.replace(/`([^`]+)`/g, '<code class="chat-inline-code">$1</code>');

        // 4. Headers: #####, ####, ###, ##, #
        escaped = escaped.replace(/^##### (.*$)/gim, '<h6 class="chat-h6">$1</h6>');
        escaped = escaped.replace(/^#### (.*$)/gim, '<h5 class="chat-h5">$1</h5>');
        escaped = escaped.replace(/^### (.*$)/gim, '<h4 class="chat-h4">$1</h4>');
        escaped = escaped.replace(/^## (.*$)/gim, '<h3 class="chat-h3">$1</h3>');
        escaped = escaped.replace(/^# (.*$)/gim, '<h2 class="chat-h2">$1</h2>');

        // 5. Horizontal rules
        escaped = escaped.replace(/^---$/gim, '<hr class="chat-hr">');

        // 6. Bold & Italic (bold-italic ***text***, bold **text**, italic *text*)
        escaped = escaped.replace(/\*\*\*([^*]+)\*\*\*/g, '<strong><em>$1</em></strong>');
        escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        escaped = escaped.replace(/\*([^*]+)\*/g, '<em>$1</em>');

        // 7. Markdown Links [text](url)
        escaped = escaped.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" class="chat-link">$1 ↗</a>');

        // 8. Blockquotes: > text
        escaped = escaped.replace(/^&gt; (.*$)/gim, '<blockquote class="chat-quote">$1</blockquote>');

        // 9. Bullet lists: - item or * item
        escaped = escaped.replace(/^\s*[-*]\s+(.*$)/gim, '<li class="chat-li">$1</li>');
        escaped = escaped.replace(/((?:<li class="chat-li">.*?<\/li>\s*)+)/gis, '<ul class="chat-ul">$1</ul>');

        // 10. Numbered lists: 1. item
        escaped = escaped.replace(/^\s*\d+\.\s+(.*$)/gim, '<li class="chat-oli">$1</li>');
        escaped = escaped.replace(/((?:<li class="chat-oli">.*?<\/li>\s*)+)/gis, '<ol class="chat-ol">$1</ol>');

        // 11. Paragraph separation
        const blocks = escaped.split(/\n{2,}/);
        let result = blocks.map(block => {
            block = block.trim();
            if (!block) return '';
            if (/^<(h[1-6]|ul|ol|div|blockquote|pre|hr|table)/i.test(block) || block.startsWith('__PHISH_CODE_BLOCK_')) {
                return block;
            }
            return `<p class="chat-p">${block.replace(/\n/g, '<br>')}</p>`;
        }).join('\n');

        // 12. Restore code blocks
        codeBlocks.forEach((cb, idx) => {
            result = result.replace(`__PHISH_CODE_BLOCK_${idx}__`, cb);
        });

        return result;
    }

    // ================================================================
    //  CONTEXT AGGREGATOR
    // ================================================================
    function gatherActiveContext() {
        const sections = [];

        if (activeContext.scan && window.PhishGuardContext && window.PhishGuardContext.getLastScan) {
            const scan = window.PhishGuardContext.getLastScan();
            if (scan && scan.analysis) {
                const psychNames = (scan.analysis.psychTriggers || []).map(p => p.name || p).join(', ');
                sections.push(`[ACTIVE THREAT SCAN CONTEXT]
- Message: "${(scan.message || '').substring(0, 300)}${scan.message && scan.message.length > 300 ? '...' : ''}"
- Risk Score: ${scan.analysis.riskScore || 0}% | Verdict: ${scan.analysis.verdict || 'Unknown'}
- Psychological Triggers: ${psychNames || 'None'}
- Extracted URLs: ${(scan.urls || []).join(', ') || 'None'}
- Threat Summary: ${scan.analysis.summary || 'N/A'}`);
            }
        }

        if (activeContext.header && window.PhishGuardContext && window.PhishGuardContext.getLastHeaderScan) {
            const header = window.PhishGuardContext.getLastHeaderScan();
            if (header && header.data) {
                const hd = header.data;
                const auth = hd.auth || {};
                const parsed = hd.parsed || {};
                sections.push(`[ACTIVE EMAIL HEADER FORENSICS]
- From: ${parsed.from || 'Unknown'} | Return-Path: ${parsed.returnPath || 'Unknown'}
- SPF: ${auth.spf || 'None'} | DKIM: ${auth.dkim || 'None'} | DMARC: ${auth.dmarc || 'None'} | Alignment: ${auth.alignment || 'Unknown'}
- Header Risk Score: ${hd.riskScore || 0}% | Verdict: ${hd.verdict || 'Unknown'}`);
            }
        }

        if (activeContext.ioc) {
            let iocs = null;
            if (window.PhishGuardContext && (window.PhishGuardContext.getExtractedIOCs || window.PhishGuardContext.getExtractedIocs)) {
                const fn = window.PhishGuardContext.getExtractedIOCs || window.PhishGuardContext.getExtractedIocs;
                iocs = fn();
            } else if (window.PhishGuardIOCStudio && window.PhishGuardIOCStudio.getExtractedIOCs) {
                iocs = window.PhishGuardIOCStudio.getExtractedIOCs();
            }
            if (iocs && iocs.length > 0) {
                const summary = iocs.slice(0, 10).map(i => `${(i.type || i.category || 'IOC').toUpperCase()}: ${i.value || i.indicator}`).join(', ');
                sections.push(`[EXTRACTED IOCs CONTEXT] (${iocs.length} Total Indicators)\n${summary}`);
            }
        }

        if (activeContext.playbook) {
            let pb = null;
            if (window.PhishGuardContext && (window.PhishGuardContext.getPlaybookState || window.PhishGuardContext.getActivePlaybook)) {
                const fn = window.PhishGuardContext.getPlaybookState || window.PhishGuardContext.getActivePlaybook;
                pb = fn();
            } else if (window.PhishGuardPlaybooks && window.PhishGuardPlaybooks.getCurrentState) {
                pb = window.PhishGuardPlaybooks.getCurrentState();
            }
            if (pb && (pb.title || pb.name)) {
                const params = pb.params || {};
                sections.push(`[SOC PLAYBOOK CONTEXT]
- Playbook: ${pb.title || pb.name || 'General Incident Response'}
- Target User: ${params.victimUser || pb.victimUser || 'Unassigned'} | Malicious Domain: ${params.maliciousDomain || pb.maliciousDomain || 'Unassigned'}`);
            }
        }

        return sections.join('\n\n');
    }
    // ================================================================
    //  BUILT-IN SOC HEURISTIC KNOWLEDGE ENGINE (Zero-Key Offline Fallback)
    // ================================================================
    function generateOfflineResponse(userQuery, contextText) {
        const intent = classifyUserIntent(userQuery);
        const q = (userQuery || '').toLowerCase().trim();

        // 1. GREETING INTENT
        if (intent === 'GREETING') {
            return `Hello! I am your **Phish-Guard AI Cyber Copilot** 🛡️. 

I am here to assist you with email header forensics, social engineering analysis, threat intelligence, and SOC incident triage. How can I help you today?

*Try asking:*
- *"How do I verify SPF, DKIM, and DMARC alignment?"*
- *"Explain how HTML Smuggling bypasses email gateways"*
- *"What are the containment steps for an AitM session hijack?"*
- *"Deconstruct the psychological triggers in this email"*`;
        }

        // 2. CASUAL THANKS INTENT
        if (intent === 'CASUAL_THANKS') {
            return `You're very welcome! Stay vigilant. Let me know if you need deeper forensic deconstruction, detection rules (YARA/Sigma/KQL), or incident response guidance.`;
        }

        // 3. META / ARCHITECTURE / IDENTITY INQUIRY
        if (intent === 'META_INQUIRY') {
            let activeEngine = 'Built-in Cognitive SOC Knowledge Base (Zero-Key Offline)';
            if (window.PhishGuardContext && window.PhishGuardContext.getAiProvider) {
                const prov = window.PhishGuardContext.getAiProvider();
                const key = window.PhishGuardContext.getApiKey ? window.PhishGuardContext.getApiKey() : '';
                const m = window.PhishGuardContext.getModel ? window.PhishGuardContext.getModel() : '';
                if (key) {
                    if (prov === 'gemini') activeEngine = `Google Gemini (${m || 'gemini-flash-latest'})`;
                    else if (prov === 'openai') activeEngine = `OpenAI (${m || 'gpt-4o-mini'})`;
                    else if (prov === 'claude') activeEngine = `Anthropic Claude (${m || 'claude-3-5-sonnet-latest'})`;
                }
            }

            return `I am **Phish-Guard AI Copilot**, an interactive cybersecurity intelligence assistant built directly into your browser.

- **Current Active Engine:** \`${activeEngine}\`
- **Supported Providers:** Google Gemini (auto-updating Flash, 3.1 Flash-Lite, 2.5 Flash/Pro), OpenAI (GPT-4o-mini, GPT-4o), Anthropic Claude (Claude 3.5/3.7), or the Zero-Key Built-in SOC Knowledge Base.
- **Privacy & Security:** Zero telemetry. API keys reside exclusively in temporary browser memory and are never saved to disk or transmitted to any third party.
- **Capabilities:** I analyze email headers (SPF/DKIM/DMARC), decode HTML smuggling payloads, deconstruct psychological social engineering cues, and generate SIEM/KQL/Sigma detection rules.`;
        }

        // 4. CONTEXT-AWARE INQUIRIES (if user asks about active scan / session findings)
        if (contextText && (q.includes('this email') || q.includes('this scan') || q.includes('this message') || q.includes('risk score') || q.includes('verdict') || q.includes('active session') || q.includes('these headers') || q.includes('explain why this') || q.includes('bulletin') || q.includes('hunting queries'))) {
            return generateContextualForensicResponse(userQuery, contextText);
        }

        if (q.includes('urgency') || q.includes('psycholog') || q.includes('emotion') || q.includes('fear') || q.includes('manipulat') || q.includes('bias')) {
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
        if (q.includes('smuggling') || q.includes('html smuggling') || q.includes('blob') || q.includes('evasion') || q.includes('base64 payload')) {
            return `### 📦 HTML Smuggling: Mechanics, Detection & Defense

**HTML Smuggling** is an advanced delivery technique where malicious payloads are synthesized *client-side* inside the victim's browser using HTML5 and JavaScript.

#### ⚙️ How HTML Smuggling Works:
1. **Payload Obfuscation:** The attacker encodes an executable or archive into a Base64 string embedded in an HTML attachment.
2. **Client-Side Assembly:** When opened, JavaScript decodes the Base64 bytes into an in-memory \`Blob\` and creates an object URL (\`window.URL.createObjectURL\`).
3. **Automatic Execution:** A dynamic \`<a>\` element with the \`download\` attribute is clicked programmatically (\`link.click()\`).
4. **Gateway Evasion:** Perimeter filters inspect only benign-looking HTML/JS code.

#### 🛡️ Detection & Hunting:
- **EDR Telemetry:** Monitor browser processes spawning script hosts (\`wscript.exe\`, \`powershell.exe\`).
- **YARA Attachment Rules:** Scan attachments for \`URL.createObjectURL\`, \`msSaveOrOpenBlob\`, and PE Base64 headers.`;
        }

        if (q.includes('quish') || q.includes('qr') || q.includes('barcode') || q.includes('camera')) {
            return `### 📱 Quishing (QR Code Phishing): Anatomy & Defenses

**Quishing** embeds malicious URLs inside QR codes in emails or attachments to bypass traditional text-based email filters.

#### 🔍 Attack Mechanics:
1. **Filter Bypass:** Traditional SEGs scan plain text links and may overlook embedded QR images.
2. **Cross-Device Pivoting:** Scanning shifts the victim to an unmanaged personal mobile device lacking corporate endpoint protections.

#### 🛡️ SOC Defenses:
- Mail gateway QR barcode automated decoding and sandboxing.
- Conditional Access enforcing managed device compliance for corporate SSO logins.`;
        }

        if (q.includes('containment') || q.includes('response') || q.includes('bec') || q.includes('aitm') || q.includes('token') || q.includes('evilginx') || q.includes('incident')) {
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

        if (q.includes('mitre') || q.includes('att&ck') || q.includes('t1566')) {
            return `### 🛡️ MITRE ATT&CK: Phishing Techniques (TA0001 - Initial Access)

- **T1566.001 (Spearphishing Attachment):** Weaponized files delivered via email (e.g. ISO images, LNK shortcuts, macro-enabled documents, HTML Smuggling).
- **T1566.002 (Spearphishing Link):** Embedded hyperlinks routing victims to credential harvesters, AitM reverse proxies, or dropper landing pages.
- **T1566.003 (Spearphishing via Service):** Phishing executed across SaaS collaboration tools (Microsoft Teams, Slack, LinkedIn InMail).
- **T1528 (Steal Application Access Token):** Illegitimate OAuth app consent grants granting persistent mailbox access without password theft.
- **T1078 (Valid Accounts):** Leveraging stolen credentials for initial domain compromise and lateral movement.`;
        }

        if (q.includes('yara') || q.includes('sigma') || q.includes('kql') || q.includes('splunk') || q.includes('rule') || q.includes('hunt')) {
            return `### 🔬 Detection Engineering & Threat Hunting Blueprint

#### 1. Microsoft Defender / Sentinel KQL Hunt:
\`\`\`kql
DeviceEvents
| where ActionType == "BrowserDownloadedFile" 
| where FileName endswith_any (".iso", ".vbs", ".exe", ".hta", ".one", ".lnk")
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFileName
| order by Timestamp desc
\`\`\`

#### 2. Sigma SIEM Rule (Suspicious Script Execution):
\`\`\`yaml
title: Suspicious Script Spawned from Office or Browser
status: production
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\winword.exe'
            - '\\excel.exe'
            - '\\chrome.exe'
            - '\\msedge.exe'
        Image|endswith:
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\powershell.exe'
    condition: selection
level: high
\`\`\``;
        }

        return `### 🛡️ SOC Security Analysis & Guidance

In modern cybersecurity operations, effective threat defense requires verifying identity at the transport and cryptographic layer (SPF/DKIM/DMARC) while combining endpoint telemetry, proactive DNS blocking, and phishing-resistant authentication (FIDO2/WebAuthn).

#### Key Triage Steps:
1. **Analyze Authentication Headers:** Verify SPF, DKIM, and DMARC alignment against the RFC 5322 \`From:\` address.
2. **Inspect Links & Attachments:** Examine URL structure for homoglyphs, lookalike domains, or HTML Smuggling payloads.
3. **Contain & Eradicate:** Revoke active refresh tokens, purge malicious emails across enterprise mailboxes, and block indicators on perimeter firewalls.

*If you have specific headers, URLs, or incident parameters to analyze, paste them here or use the quick inquiry buttons above!*`;
    }

    function generateContextualForensicResponse(userQuery, contextText) {
        let assessment = '';
        const scan = window.PhishGuardContext && window.PhishGuardContext.getLastScan ? window.PhishGuardContext.getLastScan() : null;
        const header = window.PhishGuardContext && window.PhishGuardContext.getLastHeaderScan ? window.PhishGuardContext.getLastHeaderScan() : null;

        if (scan && scan.analysis) {
            const a = scan.analysis;
            assessment += `#### 🔍 Threat Scan Assessment:\n`;
            assessment += `- **Verdict:** ${a.verdict} (Risk Score: ${a.riskScore}/100)\n`;
            if (a.summary) assessment += `- **Threat Summary:** ${a.summary}\n`;
            if (a.psychTriggers && a.psychTriggers.length) {
                assessment += `- **Cognitive Levers:** ${a.psychTriggers.map(t => `${t.name} (${t.severity})`).join(', ')}\n`;
            }
            if (a.recommendations && a.recommendations.length) {
                assessment += `\n#### 📋 Recommended Containment & Mitigation:\n`;
                a.recommendations.forEach((r, idx) => {
                    assessment += `${idx + 1}. ${r}\n`;
                });
            }
        } else if (header && header.data) {
            const hd = header.data;
            assessment += `#### 📨 Header Forensic Assessment:\n`;
            assessment += `- **Verdict:** ${hd.verdict} (Risk Score: ${hd.riskScore}/100)\n`;
            if (hd.auth) {
                assessment += `- **Authentication Status:** SPF: \`${(hd.auth.spf || 'none').toUpperCase()}\` | DKIM: \`${(hd.auth.dkim || 'none').toUpperCase()}\` | DMARC: \`${(hd.auth.dmarc || 'none').toUpperCase()}\` | Alignment: \`${(hd.auth.alignment || 'unknown').toUpperCase()}\`\n`;
            }
            if (hd.findings && hd.findings.length) {
                assessment += `\n#### 🚩 Key Forensic Indicators:\n`;
                hd.findings.forEach(f => {
                    assessment += `- ${f.icon || '⚡'} **${f.title}:** ${f.detail}\n`;
                });
            }
        } else {
            assessment += `#### 🎯 Technical Assessment:\n`;
            assessment += `1. **Risk Severity & Behavioral Breakdown:** Verify identity at the cryptographic layer (SPF/DKIM/DMARC) rather than trusting cosmetic presentation elements.\n`;
            assessment += `2. **Defensive Posture:** Do not click links or execute attachments. If credentials were submitted, immediately revoke active session tokens.`;
        }

        return `### 🔬 Forensic Analysis of Active Session Data

Based on your active Phish-Guard session findings:

${contextText.split('\n\n').map(section => {
    return `<div class="chat-context-quote"><strong>${escapeHtml(section.split('\n')[0])}</strong>\n${escapeHtml(section.split('\n').slice(1).join('\n'))}</div>`;
}).join('\n')}

${assessment}`;
    }

    // ================================================================
    //  AI API CALLS (Gemini, OpenAI & Anthropic Claude)
    // ================================================================
    async function callGeminiChat(messages, systemInstruction, apiKey, model = 'gemini-flash-latest') {
        const targetModel = model || 'gemini-flash-latest';
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(targetModel)}:generateContent?key=${encodeURIComponent(apiKey)}`;
        
        // Filter and sanitize messages for Gemini API:
        // 1. Drop leading assistant/welcome messages
        // 2. Ensure strictly alternating user/model turns starting with 'user'
        const sanitized = [];
        let expectedRole = 'user';

        for (const msg of messages) {
            const normalizedRole = msg.role === 'assistant' ? 'model' : 'user';
            if (sanitized.length === 0 && normalizedRole !== 'user') {
                continue; // First message must be 'user'
            }
            if (normalizedRole === expectedRole) {
                sanitized.push({
                    role: normalizedRole,
                    parts: [{ text: msg.content }]
                });
                expectedRole = expectedRole === 'user' ? 'model' : 'user';
            } else if (sanitized.length > 0 && normalizedRole === 'user') {
                // If consecutive user messages, combine with previous
                const last = sanitized[sanitized.length - 1];
                if (last.role === 'user') {
                    last.parts[0].text += `\n\n${msg.content}`;
                }
            }
        }

        // If empty, supply default user query
        if (sanitized.length === 0) {
            sanitized.push({
                role: 'user',
                parts: [{ text: messages[messages.length - 1]?.content || 'Hello' }]
            });
        }

        const body = {
            contents: sanitized,
            generationConfig: { temperature: 0.3, maxOutputTokens: 2048, topP: 0.95 }
        };

        if (systemInstruction) {
            body.systemInstruction = { parts: [{ text: systemInstruction }] };
        }

        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            let errMessage = '';
            try {
                const errData = await response.json();
                errMessage = (errData.error && errData.error.message) || response.statusText;
            } catch (_) {
                errMessage = await response.text();
            }
            if (response.status === 400 && String(errMessage).includes('API key')) {
                throw new Error(`Invalid Gemini API Key: ${errMessage}`);
            }
            if (response.status === 404) {
                throw new Error(`Gemini model "${targetModel}" not found (HTTP 404): ${errMessage}`);
            }
            if (response.status === 429) {
                throw new Error(`Gemini rate limit or quota exceeded (HTTP 429): ${errMessage}`);
            }
            throw new Error(`Gemini API HTTP ${response.status}: ${errMessage}`);
        }

        const data = await response.json();
        const candidate = data.candidates?.[0];
        const textPart = candidate?.content?.parts?.[0]?.text;
        if (!textPart) {
            if (candidate?.finishReason && candidate.finishReason !== 'STOP') {
                throw new Error(`Gemini response terminated early (${candidate.finishReason}).`);
            }
            throw new Error('Gemini returned an empty response.');
        }
        return textPart;
    }

    async function callOpenAIChat(messages, systemInstruction, apiKey, model = 'gpt-4o-mini') {
        const targetModel = model || 'gpt-4o-mini';
        const url = 'https://api.openai.com/v1/chat/completions';
        
        // Filter out initial welcome message if needed
        const filteredMessages = messages.filter((m, idx) => !(idx === 0 && m.role === 'assistant'));

        const openAiMessages = [
            { role: 'system', content: systemInstruction },
            ...filteredMessages.map(m => ({
                role: m.role === 'assistant' ? 'assistant' : 'user',
                content: m.content
            }))
        ];

        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
            body: JSON.stringify({ model: targetModel, messages: openAiMessages, temperature: 0.3, max_tokens: 2048 })
        });

        if (!response.ok) {
            let errMessage = '';
            try {
                const errData = await response.json();
                errMessage = (errData.error && errData.error.message) || response.statusText;
            } catch (_) {
                errMessage = await response.text();
            }
            if (response.status === 401) {
                throw new Error(`OpenAI API Key is invalid or expired (HTTP 401): ${errMessage}`);
            }
            if (response.status === 429) {
                throw new Error(`OpenAI rate limit reached or insufficient credits (HTTP 429): ${errMessage}`);
            }
            if (response.status === 404) {
                throw new Error(`OpenAI model "${targetModel}" not found (HTTP 404): ${errMessage}`);
            }
            throw new Error(`OpenAI API HTTP ${response.status}: ${errMessage}`);
        }

        const data = await response.json();
        const choice = data.choices?.[0];
        if (!choice || !choice.message?.content) {
            throw new Error('OpenAI returned an empty response.');
        }
        return choice.message.content;
    }
    async function callClaudeChat(messages, systemInstruction, apiKey, model = 'claude-3-5-sonnet-latest') {
        const targetModel = model || 'claude-3-5-sonnet-latest';
        const url = 'https://api.anthropic.com/v1/messages';
        const filteredMessages = messages.filter((m, idx) => !(idx === 0 && m.role === 'assistant'));
        const claudeMessages = filteredMessages.map(m => ({
            role: m.role === 'assistant' ? 'assistant' : 'user',
            content: m.content
        }));
        if (claudeMessages.length === 0) {
            claudeMessages.push({ role: 'user', content: 'Hello' });
        }

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01',
                'anthropic-dangerous-direct-browser-access': 'true'
            },
            body: JSON.stringify({
                model: targetModel,
                system: systemInstruction,
                max_tokens: 2048,
                messages: claudeMessages
            })
        });

        if (!response.ok) {
            let errMessage = '';
            try {
                const errData = await response.json();
                errMessage = (errData.error && errData.error.message) || response.statusText;
            } catch (_) {
                errMessage = await response.text();
            }
            if (response.status === 401) {
                throw new Error(`Claude API Key is invalid or unauthorized (HTTP 401): ${errMessage}`);
            }
            if (response.status === 429) {
                throw new Error(`Anthropic Claude rate limit reached (HTTP 429): ${errMessage}`);
            }
            if (response.status === 404) {
                throw new Error(`Claude model "${targetModel}" not found (HTTP 404): ${errMessage}`);
            }
            throw new Error(`Claude API HTTP ${response.status}: ${errMessage}`);
        }

        const data = await response.json();
        if (data.content && Array.isArray(data.content) && data.content.length > 0) {
            const textBlocks = data.content.filter(b => b.type === 'text' || b.text).map(b => b.text || '');
            if (textBlocks.length > 0) return textBlocks.join('\n');
        }
        throw new Error('Claude returned an empty response.');
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
    //  COPILOT API KEY MODAL & SETUP MANAGER
    // ================================================================
    function hasSavedApiKey() {
        let s = null;
        if (typeof window.getAISettings === 'function') {
            s = window.getAISettings();
        } else if (window.PhishGuardAISettings && typeof window.PhishGuardAISettings.getSettings === 'function') {
            s = window.PhishGuardAISettings.getSettings();
        } else {
            try {
                const raw = localStorage.getItem('pg_ai_settings');
                if (raw) s = JSON.parse(raw);
            } catch (_) {}
        }
        return !!(s && typeof s.apiKey === 'string' && s.apiKey.trim().length > 0);
    }

    function isOfflineSelected() {
        if (deliberateOfflineChoice) return true;
        try {
            if (sessionStorage.getItem('pg_copilot_offline') === 'true') return true;
        } catch (_) {}
        let s = null;
        if (typeof window.getAISettings === 'function') {
            s = window.getAISettings();
        } else if (window.PhishGuardAISettings && typeof window.PhishGuardAISettings.getSettings === 'function') {
            s = window.PhishGuardAISettings.getSettings();
        }
        return !!(s && s.provider === 'heuristic');
    }

    function updateEngineIndicatorBadge() {
        if (!dom.engineBadge) return;
        let s = null;
        if (typeof window.getAISettings === 'function') {
            s = window.getAISettings();
        } else if (window.PhishGuardAISettings && typeof window.PhishGuardAISettings.getSettings === 'function') {
            s = window.PhishGuardAISettings.getSettings();
        } else {
            s = { provider: 'gemini', model: 'gemini-flash-latest', apiKey: '' };
        }
        const prov = s.provider || 'gemini';
        const model = s.model || (window.AI_PROVIDERS_CONFIG && window.AI_PROVIDERS_CONFIG[prov]?.defaultModel) || 'gemini-flash-latest';
        const key = s.apiKey || '';

        if (prov === 'heuristic' || (!key && isOfflineSelected())) {
            dom.engineBadge.textContent = 'Engine: Built-in Heuristic SOC (Zero-Key Offline)';
            const pulse = (dom.engineIndicator && typeof dom.engineIndicator.querySelector === 'function') ? dom.engineIndicator.querySelector('.pulse-dot') : null;
            if (pulse && pulse.style) pulse.style.background = 'var(--accent-yellow)';
        } else if (key) {
            const provName = prov === 'gemini' ? 'Google Gemini'
                : prov === 'openai' ? 'OpenAI'
                : prov === 'claude' ? 'Anthropic Claude'
                : prov;
            dom.engineBadge.textContent = `Engine: ${provName} (${model})`;
            const pulse = (dom.engineIndicator && typeof dom.engineIndicator.querySelector === 'function') ? dom.engineIndicator.querySelector('.pulse-dot') : null;
            if (pulse && pulse.style) pulse.style.background = 'var(--accent-green)';
        } else {
            dom.engineBadge.textContent = 'Engine: Key Required (Offline / Setup)';
            const pulse = (dom.engineIndicator && typeof dom.engineIndicator.querySelector === 'function') ? dom.engineIndicator.querySelector('.pulse-dot') : null;
            if (pulse && pulse.style) pulse.style.background = 'var(--accent-yellow)';
        }
    }

    function populateModalModelOptions(provider, selectedModel) {
        if (!dom.modalModel) return;
        const cfg = (window.AI_PROVIDERS_CONFIG && window.AI_PROVIDERS_CONFIG[provider]) || {
            models: [{ id: 'gemini-flash-latest', label: 'Gemini Flash (Auto-Updating Latest - Recommended)' }],
            defaultModel: 'gemini-flash-latest'
        };
        dom.modalModel.innerHTML = '';
        (cfg.models || []).forEach(m => {
            const opt = document.createElement('option');
            opt.value = m.id;
            opt.textContent = m.label;
            if (m.id === selectedModel || (!selectedModel && m.id === cfg.defaultModel)) {
                opt.selected = true;
            }
            dom.modalModel.appendChild(opt);
        });
    }

    function syncModalProviderMeta(provider) {
        const cfg = (window.AI_PROVIDERS_CONFIG && window.AI_PROVIDERS_CONFIG[provider]) || {
            keyLabel: 'API Key',
            optLabel: '(BYOK)',
            placeholder: 'Enter API Key...',
            hintHtml: 'Obtain key from provider developer console.'
        };
        if (dom.modalKeyLabel) {
            dom.modalKeyLabel.innerHTML = `<span>${cfg.keyLabel || 'API Key'}</span> <span class="copilot-badge-free">${cfg.optLabel || '(BYOK)'}</span>`;
        }
        if (dom.modalApiKey) {
            dom.modalApiKey.placeholder = cfg.placeholder || 'Enter API Key...';
        }
        if (dom.modalKeyHint) {
            dom.modalKeyHint.innerHTML = cfg.hintHtml || 'Enter your API key above.';
        }
    }

    function ensureModalInDom() {
        if (dom.modalOverlay && document.body.contains(dom.modalOverlay)) return;
        let modalEl = document.getElementById('copilotSetupModal');
        if (!modalEl) {
            modalEl = document.createElement('div');
            modalEl.id = 'copilotSetupModal';
            modalEl.className = 'copilot-modal-overlay hidden';
            modalEl.setAttribute('role', 'dialog');
            modalEl.setAttribute('aria-modal', 'true');
            modalEl.setAttribute('aria-labelledby', 'copilotModalTitle');
            modalEl.innerHTML = `
                <div class="copilot-modal">
                    <button type="button" id="copilotModalClose" class="copilot-modal-close" title="Dismiss setup" aria-label="Close">&times;</button>
                    <div class="copilot-modal-header">
                        <div class="copilot-modal-icon">🤖</div>
                        <h2 id="copilotModalTitle">Set Up AI Cyber Copilot</h2>
                        <p class="copilot-modal-subtitle">Connect your AI provider API key for live neural threat reasoning, MITRE analysis, and interactive SOC guidance.</p>
                    </div>
                    <form id="copilotSetupForm" class="copilot-setup-form" onsubmit="return false;">
                        <div class="copilot-form-group">
                            <label for="copilotModalProvider" class="copilot-form-label"><span>AI Provider</span></label>
                            <select id="copilotModalProvider" class="copilot-form-select">
                                <option value="gemini">Google Gemini (Recommended Free Tier)</option>
                                <option value="openai">OpenAI (ChatGPT)</option>
                                <option value="claude">Anthropic Claude</option>
                            </select>
                        </div>
                        <div class="copilot-form-group">
                            <label for="copilotModalApiKey" id="copilotModalKeyLabel" class="copilot-form-label">
                                <span>Google Gemini API Key</span> <span class="copilot-badge-free">(Free Tier BYOK)</span>
                            </label>
                            <div class="copilot-input-key-wrapper">
                                <input type="password" id="copilotModalApiKey" class="copilot-form-input" placeholder="AIzaSy..." autocomplete="off" />
                                <button type="button" id="copilotModalKeyToggle" class="btn-copilot-key-toggle" title="Toggle visibility">👁️</button>
                            </div>
                            <div id="copilotModalKeyHint" class="copilot-form-hint">
                                Get a free API key instantly at <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener">Google AI Studio</a>.
                            </div>
                        </div>
                        <div class="copilot-form-group">
                            <label for="copilotModalModel" class="copilot-form-label">
                                <span>Model Selection</span> <span class="copilot-badge-optional">(Optional)</span>
                            </label>
                            <select id="copilotModalModel" class="copilot-form-select">
                                <option value="gemini-flash-latest">Gemini Flash (Auto-Updating Latest - Recommended)</option>
                                <option value="gemini-3.1-flash-lite">Gemini 3.1 Flash-Lite (Fast &amp; Cheap)</option>
                                <option value="gemini-2.5-flash">Gemini 2.5 Flash (Stable Fallback)</option>
                                <option value="gemini-2.5-pro">Gemini 2.5 Pro (Deep Reasoning)</option>
                                <option value="gemini-3.1-pro-preview">Gemini 3.1 Pro Preview</option>
                            </select>
                        </div>
                        <div class="copilot-privacy-callout">
                            <div class="copilot-privacy-icon">🔒</div>
                            <div class="copilot-privacy-text">
                                Your key is stored only in your browser's local storage and is sent directly to the provider you choose — never to any other server.
                            </div>
                        </div>
                        <div id="copilotModalError" class="copilot-modal-error hidden"></div>
                        <div class="copilot-modal-actions">
                            <button type="button" id="copilotModalSaveBtn" class="btn-copilot-modal-save">⚡ Save &amp; Continue</button>
                            <button type="button" id="copilotModalSkipBtn" class="btn-copilot-modal-skip">Skip / Use offline mode →</button>
                        </div>
                    </form>
                </div>
            `;
            document.body.appendChild(modalEl);
        }
        initDom();
    }

    function openSetupModal(pendingPrompt = null) {
        if (pendingPrompt) {
            pendingPromptOnSetup = pendingPrompt;
        }
        ensureModalInDom();
        if (!dom.modalOverlay) return;

        let s = null;
        if (typeof window.getAISettings === 'function') {
            s = window.getAISettings();
        } else if (window.PhishGuardAISettings && typeof window.PhishGuardAISettings.getSettings === 'function') {
            s = window.PhishGuardAISettings.getSettings();
        } else {
            s = { provider: 'gemini', model: 'gemini-flash-latest', apiKey: '' };
        }

        const activeProvider = (s.provider === 'heuristic' || !s.provider) ? 'gemini' : s.provider;
        if (dom.modalProvider) dom.modalProvider.value = activeProvider;
        populateModalModelOptions(activeProvider, s.model);
        syncModalProviderMeta(activeProvider);

        if (dom.modalApiKey) {
            dom.modalApiKey.value = s.apiKey || '';
            dom.modalApiKey.type = 'password';
        }
        if (dom.modalError) {
            dom.modalError.textContent = '';
            dom.modalError.classList.add('hidden');
        }

        dom.modalOverlay.classList.remove('hidden');
        if (dom.modalApiKey && typeof dom.modalApiKey.focus === 'function') {
            setTimeout(() => dom.modalApiKey.focus(), 150);
        }
    }

    function closeSetupModal() {
        if (dom.modalOverlay) {
            dom.modalOverlay.classList.add('hidden');
        }
        if (dom.modalError) {
            dom.modalError.textContent = '';
            dom.modalError.classList.add('hidden');
        }
    }

    function saveCopilotModalSettings() {
        const provider = dom.modalProvider ? dom.modalProvider.value : 'gemini';
        const model = dom.modalModel ? dom.modalModel.value : 'gemini-flash-latest';
        const apiKey = dom.modalApiKey ? dom.modalApiKey.value.trim() : '';

        if (!apiKey) {
            if (dom.modalError) {
                const provName = (window.AI_PROVIDERS_CONFIG && window.AI_PROVIDERS_CONFIG[provider]?.name) || provider;
                dom.modalError.textContent = `Please enter a valid API key for ${provName}, or select "Skip / Use offline mode".`;
                dom.modalError.classList.remove('hidden');
            }
            if (dom.modalApiKey && typeof dom.modalApiKey.focus === 'function') dom.modalApiKey.focus();
            return;
        }

        // Save to shared storage key 'pg_ai_settings'
        if (typeof window.saveAISettings === 'function') {
            window.saveAISettings({ provider, model, apiKey });
        } else if (window.PhishGuardAISettings && typeof window.PhishGuardAISettings.saveSettings === 'function') {
            window.PhishGuardAISettings.saveSettings({ provider, model, apiKey });
        } else {
            try {
                localStorage.setItem('pg_ai_settings', JSON.stringify({ provider, model, apiKey, vtKey: '' }));
            } catch (_) {}
        }

        // Synchronize top settings panel UI if present
        const mainProvEl = document.getElementById('ai-provider') || document.getElementById('aiProvider');
        const mainModelEl = document.getElementById('ai-model') || document.getElementById('aiModel');
        const mainKeyEl = document.getElementById('ai-api-key') || document.getElementById('apiKeyInput');
        if (mainProvEl) mainProvEl.value = provider;
        if (mainModelEl && typeof window.updateModelOptions === 'function') {
            window.updateModelOptions(mainModelEl, provider, model);
        }
        if (mainKeyEl) {
            mainKeyEl.value = apiKey;
            mainKeyEl.disabled = false;
        }

        // Reset deliberate offline choice since user now configured a real key
        deliberateOfflineChoice = false;
        try { sessionStorage.removeItem('pg_copilot_offline'); } catch (_) {}

        closeSetupModal();
        updateEngineIndicatorBadge();

        // Execute queued prompt if any
        if (pendingPromptOnSetup) {
            const p = pendingPromptOnSetup;
            pendingPromptOnSetup = null;
            sendQuery(p);
        } else if (dom.input && typeof dom.input.focus === 'function') {
            dom.input.focus();
        }
    }

    function skipToOfflineMode() {
        deliberateOfflineChoice = true;
        try { sessionStorage.setItem('pg_copilot_offline', 'true'); } catch (_) {}

        closeSetupModal();
        updateEngineIndicatorBadge();

        if (pendingPromptOnSetup) {
            const p = pendingPromptOnSetup;
            pendingPromptOnSetup = null;
            sendQuery(p);
        } else if (dom.input && typeof dom.input.focus === 'function') {
            dom.input.focus();
        }
    }

    function checkApiKeyOnCopilotOpen(pendingPrompt = null) {
        if (hasSavedApiKey()) {
            updateEngineIndicatorBadge();
            return true;
        }
        if (isOfflineSelected()) {
            updateEngineIndicatorBadge();
            return true;
        }
        // No key saved: prompt modal before chat is usable
        openSetupModal(pendingPrompt);
        return false;
    }

    // ================================================================
    //  SEND QUERY DISPATCHER
    // ================================================================
    async function sendQuery(queryText) {
        if (!dom.input || !dom.btnSend) initDom();
        const text = (queryText !== undefined && queryText !== null ? queryText : (dom.input ? dom.input.value : '') || '').trim();
        if (!text || isProcessing) return;

        // Check if API key is configured or offline mode deliberately selected
        if (!hasSavedApiKey() && !isOfflineSelected()) {
            openSetupModal(text);
            return;
        }

        isProcessing = true;
        if (dom.btnSend) dom.btnSend.disabled = true;
        if (dom.input) {
            dom.input.value = '';
            dom.input.style.height = 'auto';
        }

        const timestamp = Date.now();
        chatHistory.push({ role: 'user', content: text, timestamp: timestamp });
        appendMessage('user', text, timestamp);

        showTypingIndicator();

        try {
            let provider = 'gemini';
            let key = '';
            let aiModel = '';

            // Retrieve configured provider, key, and model
            if (typeof window.getAISettings === 'function') {
                const s = window.getAISettings();
                provider = s.provider || 'gemini';
                key = s.apiKey || '';
                aiModel = s.model || '';
            } else if (window.PhishGuardAISettings && typeof window.PhishGuardAISettings.getSettings === 'function') {
                const s = window.PhishGuardAISettings.getSettings();
                provider = s.provider || 'gemini';
                key = s.apiKey || '';
                aiModel = s.model || '';
            } else {
                try {
                    const raw = localStorage.getItem('pg_ai_settings');
                    if (raw) {
                        const s = JSON.parse(raw);
                        provider = s.provider || 'gemini';
                        key = s.apiKey || '';
                        aiModel = s.model || '';
                    }
                } catch (_) {}
            }

            if (!key && window.PhishGuardContext && typeof window.PhishGuardContext.getApiKey === 'function') {
                key = window.PhishGuardContext.getApiKey() || '';
            }
            if (!key) {
                const domKeyEl = document.getElementById('ai-api-key') || document.getElementById('apiKeyInput');
                if (domKeyEl && domKeyEl.value) {
                    key = domKeyEl.value.trim();
                }
            }
            if (!provider && window.PhishGuardContext && typeof window.PhishGuardContext.getAiProvider === 'function') {
                provider = window.PhishGuardContext.getAiProvider() || 'gemini';
            }
            if (!provider) {
                const domProvEl = document.getElementById('ai-provider') || document.getElementById('aiProvider');
                if (domProvEl && domProvEl.value) {
                    provider = domProvEl.value;
                }
            }
            if (!aiModel && window.PhishGuardContext && typeof window.PhishGuardContext.getModel === 'function') {
                aiModel = window.PhishGuardContext.getModel() || '';
            }
            if (!aiModel) {
                const domModelEl = document.getElementById('ai-model') || document.getElementById('aiModel');
                if (domModelEl && domModelEl.value) {
                    aiModel = domModelEl.value;
                }
            }

            const intent = classifyUserIntent(text);
            const contextData = gatherActiveContext();

            // Dynamic system instruction with optional forensic context for threat queries
            let systemInstruction = UPDATED_SOC_SYSTEM_PROMPT;
            if (contextData && (intent === 'THREAT_ANALYSIS' || intent === 'GENERAL_INQUIRY')) {
                systemInstruction += `\n\n--- ACTIVE FORENSIC SESSION CONTEXT (Use if relevant to the inquiry) ---\n${contextData}\n--- END OF CONTEXT ---`;
            }

            let replyText = '';
            let engineName = 'Built-in SOC Knowledge Base';

            if (provider === 'gemini' && key) {
                engineName = `Google Gemini (${aiModel || 'gemini-flash-latest'})`;
                if (dom.engineBadge) dom.engineBadge.textContent = `Engine: ${engineName}`;
                const apiMessages = chatHistory.map(m => ({
                    role: m.role,
                    content: m.content
                }));
                replyText = await callGeminiChat(apiMessages, systemInstruction, key, aiModel || 'gemini-flash-latest');
            } else if (provider === 'openai' && key) {
                engineName = `OpenAI (${aiModel || 'gpt-4o-mini'})`;
                if (dom.engineBadge) dom.engineBadge.textContent = `Engine: ${engineName}`;
                const apiMessages = chatHistory.map(m => ({
                    role: m.role,
                    content: m.content
                }));
                replyText = await callOpenAIChat(apiMessages, systemInstruction, key, aiModel || 'gpt-4o-mini');
            } else if (provider === 'claude' && key) {
                engineName = `Anthropic Claude (${aiModel || 'claude-3-5-sonnet-latest'})`;
                if (dom.engineBadge) dom.engineBadge.textContent = `Engine: ${engineName}`;
                const apiMessages = chatHistory.map(m => ({
                    role: m.role,
                    content: m.content
                }));
                replyText = await callClaudeChat(apiMessages, systemInstruction, key, aiModel || 'claude-3-5-sonnet-latest');
            } else {
                if (dom.engineBadge) dom.engineBadge.textContent = 'Engine: Built-in SOC Knowledge Base';
                await new Promise(r => setTimeout(r, 300));
                replyText = generateOfflineResponse(text, intent === 'THREAT_ANALYSIS' ? contextData : '');
            }

            removeTypingIndicator();
            const botTimestamp = Date.now();
            chatHistory.push({ role: 'assistant', content: replyText, timestamp: botTimestamp });
            appendMessage('assistant', replyText, botTimestamp);

            // Persist incident briefing to Forensic Threat Vault
            try {
                if (window.PhishGuardDB && typeof window.PhishGuardDB.recordCopilotBriefing === 'function') {
                    window.PhishGuardDB.recordCopilotBriefing({
                        prompt: text,
                        response: replyText,
                        engine: engineName,
                        timestamp: new Date(botTimestamp).toISOString()
                    });
                }
            } catch (dbErr) {
                console.warn('[Copilot DB Recording Error]:', dbErr);
            }

        } catch (err) {
            removeTypingIndicator();
            console.error('[Phish-Guard Copilot Error]:', err);
            
            const providerDisplayName = provider === 'gemini' ? 'Google Gemini'
                : provider === 'openai' ? 'OpenAI'
                : provider === 'claude' ? 'Anthropic Claude'
                : 'AI Engine';

            const errorMsg = `### ❌ ${providerDisplayName} Request Failed\n\n**Error Details:** \`${err.message || 'Unable to connect to AI provider.'}\`\n\n- **Target Model:** \`${aiModel || 'default'}\`\n- **Engine Status:** Live API call failed.\n\n💡 **Troubleshooting:**\n1. Check your API key in **AI Settings** (top header).\n2. Verify the selected model is active and your quota is not exceeded.\n3. If offline, switch provider to **"Built-in Heuristic SOC Engine (Zero-Key Offline)"** in AI Settings.`;

            chatHistory.push({ role: 'assistant', content: errorMsg, timestamp: Date.now() });
            appendMessage('assistant', errorMsg, Date.now());
            if (dom.engineBadge) dom.engineBadge.textContent = `Engine: ${providerDisplayName} (Error)`;
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

I am your **conversational AI Cybersecurity & Threat Intelligence Assistant**. I can help you with:

- 🔍 **Deconstructing Threats:** Explain social engineering tactics, cognitive manipulation, and attack vectors.
- 📨 **Email Header Forensics:** Inspect SPF, DKIM, DMARC alignment, and routing hops.
- 📦 **Evasion & Smuggling:** Analyze HTML Smuggling, Base64 Blobs, and IDN Homoglyph spoofing.
- 🛡️ **SOC Incident Triage:** Generate KQL hunt queries, Sigma rules, PowerShell containment scripts, and mitigation playbooks.

*Ask any cybersecurity question, chat casually, or click one of the quick prompts above to get started!*`;

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
        if (dom.btnSend) {
            dom.btnSend.addEventListener('click', () => sendQuery());
        }

        if (dom.input) {
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
        }

        if (dom.btnClear) dom.btnClear.addEventListener('click', clearChat);
        if (dom.btnExport) dom.btnExport.addEventListener('click', exportTranscript);

        // Modal Action Bindings
        if (dom.modalSaveBtn) {
            dom.modalSaveBtn.addEventListener('click', () => saveCopilotModalSettings());
        }
        if (dom.modalSkipBtn) {
            dom.modalSkipBtn.addEventListener('click', () => skipToOfflineMode());
        }
        if (dom.modalClose) {
            dom.modalClose.addEventListener('click', () => {
                deliberateOfflineChoice = true;
                closeSetupModal();
            });
        }
        if (dom.modalProvider) {
            dom.modalProvider.addEventListener('change', (e) => {
                const prov = e.target.value;
                populateModalModelOptions(prov);
                syncModalProviderMeta(prov);
            });
        }
        if (dom.modalKeyToggle && dom.modalApiKey) {
            dom.modalKeyToggle.addEventListener('click', () => {
                dom.modalApiKey.type = dom.modalApiKey.type === 'password' ? 'text' : 'password';
            });
        }
        if (dom.modalOverlay) {
            dom.modalOverlay.addEventListener('click', (e) => {
                if (e.target === dom.modalOverlay) {
                    deliberateOfflineChoice = true;
                    closeSetupModal();
                }
            });
        }
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && dom.modalOverlay && !dom.modalOverlay.classList.contains('hidden')) {
                deliberateOfflineChoice = true;
                closeSetupModal();
            }
        });

        if (dom.btnConfig) {
            dom.btnConfig.addEventListener('click', (e) => {
                e.stopPropagation();
                openSetupModal();
            });
        }
        if (dom.engineIndicator) {
            dom.engineIndicator.addEventListener('click', () => {
                openSetupModal();
            });
        }

        // Tab open detection for Copilot
        const copilotTabBtns = document.querySelectorAll('#tabCopilotBtn, [data-tab="copilotTab"]');
        copilotTabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                setTimeout(() => checkApiKeyOnCopilotOpen(), 50);
            });
        });

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

        if (dom.promptButtons) {
            dom.promptButtons.forEach(btn => {
                btn.addEventListener('click', () => {
                    const prompt = btn.dataset.prompt;
                    if (prompt) {
                        if (dom.input) dom.input.value = prompt;
                        sendQuery(prompt);
                    }
                });
            });
        }
    }
    // ================================================================
    //  PUBLIC API FOR INTEGRATION
    // ================================================================
    window.PhishGuardCopilot = {
        init: function () {
            initDom();
            bindEvents();
            renderWelcomeMessage();
            updateEngineIndicatorBadge();

            const copilotTabEl = document.getElementById('copilotTab');
            if (copilotTabEl && copilotTabEl.classList.contains('active')) {
                setTimeout(() => checkApiKeyOnCopilotOpen(), 100);
            }
        },

        onTabOpen: function (pendingPrompt) {
            return checkApiKeyOnCopilotOpen(pendingPrompt);
        },

        openSetupModal: function (pendingPrompt) {
            openSetupModal(pendingPrompt);
        },

        closeSetupModal: function () {
            closeSetupModal();
        },

        updateBadge: function () {
            updateEngineIndicatorBadge();
        },

        hasApiKey: function () {
            return hasSavedApiKey();
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
                if (dom.input) dom.input.value = promptText;
                if (!hasSavedApiKey() && !isOfflineSelected()) {
                    openSetupModal(promptText);
                    return;
                }
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