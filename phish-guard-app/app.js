/**
 * Phish-Guard - AI & Cognitive Social Engineering Platform
 * ---------------------------------------------------------
 * Multi-Model BYOK Architecture:
 * - Google Gemini (Gemini 1.5 Flash - Free Tier)
 * - OpenAI (GPT-4o-mini)
 * - Local Cognitive & Heuristic Fallback Engine (Zero-Key Offline)
 * - VirusTotal Threat Intelligence Feed
 */
(function () {
    'use strict';

    // ================================================================
    //  STATE (In-Memory Only)
    // ================================================================
    let aiProvider = 'gemini';
    let apiKey     = '';
    let vtKey      = '';
    let lastScanData = null;

    const PROVIDER_META = {
        gemini: {
            label: 'Google Gemini API Key',
            opt: '(Free Tier)',
            hintHtml: 'Free key from <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener">Google AI Studio</a>.'
        },
        openai: {
            label: 'OpenAI API Key',
            opt: '',
            hintHtml: 'Requires a billed OpenAI account (GPT-4o-mini). No key? Use Gemini or the offline heuristic engine.'
        },
        heuristic: {
            label: 'Built-in Heuristic Engine',
            opt: '(No API key required)',
            hintHtml: 'Fully offline cognitive + pattern analysis. No network calls for message analysis.'
        }
    };

    // Simulator State
    let currentSimIndex = 0;
    let simStats = { attempted: 0, correct: 0 };
    let simAnswers = {};

    // ================================================================
    //  SAMPLE PRESETS
    // ================================================================
    const SAMPLES = {
        bank: "ALERT from Chase Fraud Dept: A debit card charge of $842.19 at Walmart Online was attempted on your account. If this was NOT you, immediately verify your identity to prevent permanent account suspension: https://chase-security-verify.xyz/login?session=92841",
        ceo: "Hi, I am currently in an executive board meeting and cannot take calls. I need you to purchase 5x $100 Apple Gift Cards for a VIP client presentation immediately. Scratch the back, take clear photos of the PINs and reply to this email right away. Please handle this discreetly. Thanks, David (CEO)",
        package: "USPS: We attempted delivery of your package #US-98218-99 today, but the address on file was incomplete. Please update your delivery coordinates within 12 hours or the package will be returned to sender: http://192.168.1.104/usps-redelivery.php",
        creds: "IT Helpdesk Notice: Your Microsoft 365 enterprise password expires in 2 hours. Failure to validate credentials will result in immediate revocation of your corporate email and VPN access. Keep your existing password by confirming here: https://login-microsoftonline.account-update.top/auth",
        payroll: "HR Compensation Notice: An unadjusted Q3 performance bonus of $1,450.00 is pending approval for your employee profile. You must review and confirm your direct deposit details before 5:00 PM today to receive disbursement: https://workday-payroll-portal.click/claim-bonus",
        legit: "Hi team,\n\nJust a quick reminder about our Q3 Project Review tomorrow at 2:00 PM in Conference Room B. Please review the attached slide deck in our shared Google Drive folder prior to the call.\n\nBest regards,\nSarah Jenkins\nProject Lead"
    };

    // ================================================================
    //  SIMULATOR SCENARIOS
    // ================================================================
    const SIM_SCENARIOS = [
        {
            category: "Executive Whaling (BEC)",
            difficulty: "Intermediate",
            diffClass: "diff-med",
            from: "David Miller <david.miller.ceo@corp-executive-mail.com>",
            subject: "URGENT: Confidential Client Gift Cards Request",
            body: "Hi,\n\nI'm tied up in confidential merger negotiations and cannot take calls. I need an urgent favor—please purchase 4x $200 Apple Gift Cards for our prospective partners right now.\n\nScratch the security film on the back, take crisp photos of the PIN codes, and email them back to me directly. I will authorize your expense reimbursement first thing tomorrow morning.\n\nPlease handle this discreetly and quickly.\n\nBest,\nDavid Miller\nChief Executive Officer",
            isPhish: true,
            title: "Classic Business Email Compromise (BEC)",
            explanation: "This is a textbook Executive Whaling attack using a lookalike external domain ('@corp-executive-mail.com') to spoof the CEO.",
            cognitiveBiases: [
                "Manufactured Authority (CEO title overrides verification)",
                "Artificial Urgency ('right now', 'tied up in negotiations')",
                "Isolation / Secrecy ('handle this discreetly', 'cannot take calls')"
            ],
            indicators: [
                "Unusual payment method (untraceable gift cards)",
                "Mismatched external sender domain pretending to be internal leadership",
                "Pressure to bypass normal financial procurement controls"
            ],
            coaching: "Never purchase gift cards or execute financial transactions based solely on email requests. Always verify out-of-band via phone or Slack."
        },
        {
            category: "Financial Smishing / Brand Spoofing",
            difficulty: "Easy",
            diffClass: "diff-easy",
            from: "Chase Alert Service <alerts@chase-security-verify.xyz>",
            subject: "URGENT FRAUD ALERT: Unauthorized Debit Transaction $842.19",
            body: "CHASE SECURITY NOTIFICATION:\n\nWe detected an unauthorized charge of $842.19 at Walmart.com on your card ending in 4108.\n\nTo reverse this charge and prevent permanent suspension of all banking privileges, you must verify your identity immediately at:\nhttps://chase-security-verify.xyz/auth?id=88319\n\nFailure to respond within 1 hour will result in card cancellation.",
            isPhish: true,
            title: "Urgent Financial Coercion Scam",
            explanation: "The attacker exploits high-stress panic by inventing a large unauthorized charge to force a rushed click on a phishing domain.",
            cognitiveBiases: [
                "Fear & Panic (threat of losing $842.19 and account suspension)",
                "High Urgency ('within 1 hour', 'immediately')",
                "False Authority (impersonating bank fraud department)"
            ],
            indicators: [
                "Suspicious TLD (.xyz) completely unrelated to legitimate chase.com",
                "Coercive deadline intended to short-circuit critical thinking",
                "Generic greeting without actual account holder name"
            ],
            coaching: "Legitimate banks never threaten immediate permanent account closure within 1 hour or ask you to verify credentials on .xyz domains."
        },
        {
            category: "Credential Harvester (M365)",
            difficulty: "Intermediate",
            diffClass: "diff-med",
            from: "IT Helpdesk <support@login-microsoftonline.account-update.top>",
            subject: "Action Required: Microsoft 365 Password Expiry Warning",
            body: "Attention Corporate User:\n\nYour Microsoft 365 enterprise password will expire in 2 hours. Once expired, you will be locked out of Outlook, Teams, and VPN services.\n\nIf you wish to retain your current password without disruption, confirm your identity here:\nhttps://login-microsoftonline.account-update.top/sso-login\n\nIT Operations & Security Team",
            isPhish: true,
            title: "Corporate SSO Credential Harvest",
            explanation: "The email impersonates internal IT support to steal corporate Single Sign-On (SSO) login credentials.",
            cognitiveBiases: [
                "Loss Aversion (fear of losing workflow and VPN access)",
                "Convenience Trap ('Keep your current password')",
                "Institutional Authority ('IT Operations & Security')"
            ],
            indicators: [
                "Domain spoofing: '.account-update.top' is the actual domain, with 'login-microsoftonline' merely a subdomain",
                "High-risk top-level domain (.top)",
                "Policy contradiction: Real IT departments never let you bypass password expiry rules by 'confirming' old passwords"
            ],
            coaching: "Always inspect the root domain before entering credentials. Legitimate Microsoft logins reside on microsoftonline.com."
        },
        {
            category: "Financial Lure (HR Payroll)",
            difficulty: "Advanced",
            diffClass: "diff-hard",
            from: "HR Benefits Notification <payroll@workday-payroll-portal.click>",
            subject: "Notification: Unclaimed Q3 Discretionary Bonus Allocation ($1,450.00)",
            body: "Dear Colleague,\n\nYou have a pending performance bonus payout of $1,450.00 that has not been claimed due to outdated bank routing details.\n\nPlease confirm your direct deposit details before 5:00 PM today to ensure inclusion in this week's direct deposit cycle:\nhttps://workday-payroll-portal.click/claim-bonus\n\nHuman Resources & Total Rewards",
            isPhish: true,
            title: "HR Compensation Baiting Attack",
            explanation: "Attackers use positive emotional stimuli (unexpected bonus) paired with a tight deadline to bait employees into surrendering banking details.",
            cognitiveBiases: [
                "Greed / Excitement (unexpected financial reward)",
                "Loss Aversion (fear of missing out on $1,450 by 5:00 PM deadline)",
                "Corporate Authority (HR & Total Rewards)"
            ],
            indicators: [
                "Fake HR domain (.click) spoofing Workday",
                "Asking for sensitive banking credentials via an external web link",
                "Artificial 5:00 PM deadline to discourage verifying with real HR"
            ],
            coaching: "Never click external links to enter banking details. Navigate to your corporate HR/Workday portal independently."
        },
        {
            category: "MFA Fatigue / Push Authorization",
            difficulty: "Advanced",
            diffClass: "diff-hard",
            from: "Duo Security Alerts <no-reply@duo-security-mfa-verify.net>",
            subject: "Security Alert: New Sign-in Attempt from St. Petersburg, Russia",
            body: "Duo Two-Factor Authentication:\n\nA login attempt was detected from IP 185.220.101.5 (St. Petersburg, Russia) for your workstation profile.\n\nIf this was NOT you, tap below immediately to reject the request and secure your token:\nhttps://duo-security-mfa-verify.net/revoke-session\n\nDuo Security Protection System",
            isPhish: true,
            title: "MFA Token Revocation Phish",
            explanation: "Capitalizes on alarm over a foreign sign-in to trick users into visiting a fake portal where their actual MFA token is stolen.",
            cognitiveBiases: [
                "Fear of Foreign Intrusion ('St. Petersburg, Russia')",
                "Urgent Defensive Reaction (rushing to 'block' the attacker)",
                "Technical Authority (Duo Security)"
            ],
            indicators: [
                "Fake vendor domain: duo-security-mfa-verify.net instead of official duosecurity.com",
                "Reverse psychology: Posing as a defensive security alert to execute an attack"
            ],
            coaching: "When receiving unexpected MFA alerts, open your official authenticator app or contact your IT helpdesk directly."
        },
        {
            category: "Legitimate Corporate Communication",
            difficulty: "Easy",
            diffClass: "diff-easy",
            from: "Sarah Jenkins <sjenkins@acmecorp.com>",
            subject: "Reminder: Q3 Project Review Tomorrow at 2:00 PM",
            body: "Hi team,\n\nJust a quick reminder about our Q3 Project Review meeting scheduled for tomorrow at 2:00 PM in Conference Room B / Google Meet.\n\nPlease review the summary deck in our corporate Google Drive folder prior to the call so we can focus our time on Q4 milestones.\n\nMeeting Link: https://meet.google.com/abc-defg-hij\n\nBest regards,\nSarah Jenkins\nSenior Project Manager\nAcme Corp",
            isPhish: false,
            title: "Legitimate Workplace Communication",
            explanation: "This is a routine, non-threatening internal meeting reminder with no coercive emotional manipulation or deceptive indicators.",
            cognitiveBiases: [
                "No artificial panic or aggressive countdowns",
                "Reasonable business context and polite professional tone"
            ],
            indicators: [
                "Valid corporate sender address (@acmecorp.com)",
                "Legitimate Google Meet conferencing domain (meet.google.com)",
                "No requests for credentials, passwords, gift cards, or urgent financial changes"
            ],
            coaching: "Notice the absence of false urgency, suspicious domain mismatches, or requests for sensitive information."
        }
    ];

    // ================================================================
    //  DOM REFERENCES
    // ================================================================
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dom = {
        keyToggle:        $('#keyToggle'),
        keyPanel:         $('#keyPanel'),
        aiProviderSelect: $('#aiProvider'),
        apiKeyLabel:      $('#apiKeyLabel'),
        apiKeyHint:       $('#apiKeyHint'),
        apiKeyInput:      $('#apiKeyInput'),
        vtInput:          $('#vtKey'),
        messageInput:     $('#messageInput'),
        scanButton:       $('#scanButton'),
        clearBtn:         $('#clearBtn'),
        loading:          $('#loading'),
        statusText:       $('#statusText'),
        resultArea:       $('#resultArea'),
        sampleBtns:       $$('.btn-sample'),

        // -- Simulator (Security Awareness Lab) --
        simCurrentIndex:       $('#simCurrentIndex'),
        simScore:              $('#simScore'),
        simScoreRatio:         $('#simScoreRatio'),
        simScenarioCategory:   $('#simScenarioCategory'),
        simScenarioDifficulty: $('#simScenarioDifficulty'),
        simFrom:               $('#simFrom'),
        simSubject:            $('#simSubject'),
        simBody:               $('#simBody'),
        simDecisionArea:       $('#simDecisionArea'),
        simFeedbackArea:       $('#simFeedbackArea'),
        btnJudgePhish:         $('#btnJudgePhish'),
        btnJudgeSafe:          $('#btnJudgeSafe'),
        btnPrevSim:            $('#btnPrevSim'),
        btnNextSim:            $('#btnNextSim'),
        btnGenerateChallenge:  $('#btnGenerateChallenge'),
        btnResetSimulator:     $('#btnResetSimulator'),
    };

    // ================================================================
    //  INIT - Event Listeners
    // ================================================================
    dom.keyToggle.addEventListener('click', toggleKeyPanel);
    dom.aiProviderSelect.addEventListener('change', onProviderChange);
    dom.apiKeyInput.addEventListener('input', (e) => { apiKey = e.target.value.trim(); });
    dom.vtInput.addEventListener('input',     (e) => { vtKey  = e.target.value.trim(); });
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

    // Initialize tabs & simulator
    initTabs();
    initSimulator();

    // Wire simulator action buttons
    if (dom.btnGenerateChallenge) {
        dom.btnGenerateChallenge.addEventListener('click', generateAIScenario);
    }
    if (dom.btnResetSimulator) {
        dom.btnResetSimulator.addEventListener('click', resetSimulator);
    }

    // Sync provider UI on load
    onProviderChange();

    // Wipe keys on unload
    window.addEventListener('beforeunload', () => {
        apiKey = '';
        vtKey  = '';
    });

    // ================================================================
    //  UI HELPERS
    // ================================================================
    function toggleKeyPanel() {
        const isCollapsed = dom.keyPanel.classList.toggle('collapsed');
        dom.keyToggle.setAttribute('aria-expanded', !isCollapsed);
    }

    function initTabs() {
        const tabs = $$('.tab-btn');
        tabs.forEach((btn) => {
            btn.addEventListener('click', () => {
                tabs.forEach((b) => b.classList.remove('active'));
                btn.classList.add('active');
                $$('.tab-content').forEach((c) => c.classList.remove('active'));
                const target = document.getElementById(btn.dataset.tab);
                if (target) target.classList.add('active');
            });
        });
    }

    function onProviderChange() {
        aiProvider = dom.aiProviderSelect.value;
        const meta = PROVIDER_META[aiProvider] || PROVIDER_META.gemini;
        dom.apiKeyInput.disabled = (aiProvider === 'heuristic');
        dom.apiKeyLabel.innerHTML = escapeHtml(meta.label) +
            (meta.opt ? ' <span class="opt">' + escapeHtml(meta.opt) + '</span>' : '');
        dom.apiKeyHint.innerHTML = meta.hintHtml;
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

            // 3 - Engine Selection: Gemini / OpenAI / Heuristic
            let analysis = null;
            let engineUsed = '';

            if (aiProvider !== 'heuristic' && !apiKey) {
                throw new Error('An API key is required for the ' +
                    (aiProvider === 'gemini' ? 'Gemini' : 'OpenAI') +
                    ' engine. Enter your key above, or switch to the Built-in Heuristic Engine.');
            }

            if (aiProvider === 'gemini' && apiKey) {
                setStatus('Running Google Gemini 1.5 Flash neural + psych analysis...');
                analysis = await analyzeWithGemini(message, urls, apiKey);
                engineUsed = 'AI (Gemini 1.5 Flash)';
            } else if (aiProvider === 'openai' && apiKey) {
                setStatus('Running OpenAI GPT-4o-mini neural analysis...');
                analysis = await analyzeWithOpenAI(message, urls, apiKey);
                engineUsed = 'AI (GPT-4o-mini)';
            } else {
                setStatus('Running built-in Heuristic + Cognitive Analysis Engine...');
                await new Promise(r => setTimeout(r, 450));
                analysis = analyzeHeuristics(message, urls);
                engineUsed = 'Local Heuristic Engine';
            }

            // Ensure results always include psych + plain-English layers
            analysis = normalizeAnalysis(analysis, message, urls);

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
    //  PSYCHOLOGICAL / COGNITIVE ANALYSIS LAYER
    // ================================================================
    const PSYCH_LIBRARY = [
        {
            name: 'False Urgency (Time Pressure)',
            icon: '⏰',
            severity: 'high',
            patterns: [/\b(immediately|urgent|right away|act now|within \d+\s*hours?|by .*pm|asap|at once|no later than)\b/i],
            description: 'Attackers compress your decision window so you skip verification and act on emotion.'
        },
        {
            name: 'Authority Impersonation',
            icon: '👔',
            severity: 'high',
            patterns: [/\b(ceo|cfo|executive|board|director|owner|manager)\b/i, /\b(helpdesk|it department|hr department|payroll|security team|fraud department)\b/i],
            description: 'Impersonating executives or trusted departments leverages natural obedience to authority figures.'
        },
        {
            name: 'Fear & Intimidation',
            icon: '⚠️',
            severity: 'high',
            patterns: [/\b(suspended|deactivated|terminated|permanently|revoked|arrest|legal action|lawsuit|compromised)\b/i],
            description: 'Threats of loss trigger fight-or-flight, overriding rational decision-making.'
        },
        {
            name: 'Curiosity Bait / Open Loop',
            icon: '🎣',
            severity: 'med',
            patterns: [/\b(unusual activity|unauthorized|you have (a new|received)|claim (your|this)|check (this|what)|exclusive|secret|confidential)\b/i],
            description: 'Open loops exploit the brain\'s compulsion to resolve ambiguity and incomplete information.'
        },
        {
            name: 'Scarcity / Reward Lure',
            icon: '🎁',
            severity: 'med',
            patterns: [/\b(bonus|prize|reward|refund|gift card|discount|limited time|only \d+ (left|remaining)|claim bonus)\b/i],
            description: 'Reward framing suppresses skepticism by activating desire and loss-aversion circuits.'
        },
        {
            name: 'Credential Harvesting',
            icon: '🔐',
            severity: 'high',
            patterns: [/\b(password|credentials|sign.in|verify your (identity|account)|confirm your (password|login)|validate your)\b/i],
            description: 'The attacker\'s end goal — tricking you into entering credentials on a spoofed portal.'
        }
    ];

    function detectPsychTriggers(text) {
        var triggers = [];
        var lower = text.toLowerCase();
        PSYCH_LIBRARY.forEach(function (t) {
            var matched = null;
            t.patterns.forEach(function (rx) {
                var m = lower.match(rx);
                if (m && !matched) matched = m[0];
            });
            if (matched) {
                triggers.push({
                    name: t.name, icon: t.icon, severity: t.severity,
                    quote: matched.replace(/\s+/g, ' ').trim().slice(0, 80),
                    description: t.description
                });
            }
        });
        return triggers;
    }

    function buildPlainEnglish(score, verdict, cues, urls) {
        var cueList = cues && cues.length
            ? cues.map(function (c) { return c.replace(/^(Social Engineering: |T\d+(\.\d+)?[a-z]*: )/gi, '').toLowerCase(); }).join(', ')
            : null;

        var tlDr;
        if (verdict === 'SAFE') tlDr = 'No need to panic — this message shows no warning signs and appears legitimate.';
        else if (verdict === 'SUSPICIOUS') tlDr = 'We are not sure about this one. It has patterns often seen in scams — verify before trusting it.';
        else tlDr = 'Do not click, reply, or share any details — this message is most likely an attempt to trick you.';

        var whatWeFound = 'We analyzed the wording' + (urls && urls.length ? ' and the link(s) inside' : '') + '. ';
        whatWeFound += cueList
            ? 'It uses techniques like ' + cueList + ' to pressure or deceive you.'
            : 'We did not find obvious scam language or suspicious links.';

        var whyItMatters = verdict === 'SAFE'
            ? 'Even safe-looking messages deserve a quick sender check — attackers mimic everyday emails all the time.'
            : 'A single click or shared credential can give attackers access to your accounts, data, and company network.';

        return { tlDr: tlDr, whatWeFound: whatWeFound, whyItMatters: whyItMatters };
    }

    function sanitizePsychTriggers(arr) {
        if (!Array.isArray(arr)) return [];
        return arr.filter(function (t) { return t && t.name; }).map(function (t) {
            return {
                name: String(t.name),
                icon: String(t.icon || '🧠'),
                severity: (['high', 'med', 'low'].indexOf(t.severity) >= 0) ? t.severity : 'med',
                quote: String(t.quote || ''),
                description: String(t.description || '')
            };
        });
    }

    function normalizeAnalysis(ai, message, urls) {
        if (!ai || typeof ai !== 'object') ai = {};
        var h = analyzeHeuristics(message, urls || extractURLs(message));
        var result = {
            riskScore: Number.isFinite(Number(ai.riskScore))
                ? Math.max(0, Math.min(100, Math.round(Number(ai.riskScore))))
                : h.riskScore,
            verdict: (['SAFE', 'SUSPICIOUS', 'PHISHING'].indexOf((ai.verdict || '').toUpperCase()) >= 0)
                ? ai.verdict.toUpperCase()
                : h.verdict,
            techniques: (Array.isArray(ai.techniques) && ai.techniques.length) ? ai.techniques.map(String) : h.techniques,
            summary: (ai.summary && String(ai.summary).trim()) ? String(ai.summary) : h.summary,
            recommendations: (Array.isArray(ai.recommendations) && ai.recommendations.length) ? ai.recommendations.map(String) : h.recommendations,
            psychTriggers: sanitizePsychTriggers(ai.psychTriggers),
            plainEnglish: (ai.plainEnglish && ai.plainEnglish.tlDr)
                ? {
                    tlDr: String(ai.plainEnglish.tlDr),
                    whatWeFound: String(ai.plainEnglish.whatWeFound || ''),
                    whyItMatters: String(ai.plainEnglish.whyItMatters || '')
                }
                : h.plainEnglish
        };
        if (!result.psychTriggers.length) result.psychTriggers = h.psychTriggers;
        return result;
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
            recommendations: recommendations,
            psychTriggers: detectPsychTriggers(text),
            plainEnglish: buildPlainEnglish(score, verdict, detectedCues, urls)
        };
    }

    // ================================================================
    //  OPENAI GPT-4o-mini ANALYSIS ENGINE
    // ================================================================
    async function analyzeWithOpenAI(message, urls, apiKey) {
        const systemPrompt = `You are a Senior Cybersecurity Threat Analyst specializing in Social Engineering, MITRE ATT&CK T1566 (Phishing), BEC (Business Email Compromise), and cognitive psychology.
Analyze the provided message text and list of extracted URLs.

Respond ONLY with a valid, raw JSON object matching this schema (no markdown fences, no explanatory text outside JSON):
{
  "riskScore": <integer 0 to 100>,
  "verdict": "<SAFE | SUSPICIOUS | PHISHING>",
  "techniques": ["<MITRE ATT&CK or Social Engineering technique tag, e.g. T1566.002: Spearphishing Link, Artificial Urgency, Executive Impersonation, Credential Harvesting>"],
  "summary": "<2-3 sentence concise threat analysis explaining why the message is safe, suspicious, or malicious>",
  "recommendations": ["<Actionable mitigation step 1>", "<Actionable mitigation step 2>", "<Actionable mitigation step 3>"],
  "psychTriggers": [
    {
      "name": "<Psychological tactic exploited, e.g. False Urgency, Authority Impersonation, Fear & Intimidation, Curiosity Bait, Scarcity, Social Proof, Credential Harvesting>",
      "icon": "<single emoji representing the tactic>",
      "severity": "<high | med | low>",
      "quote": "<exact short phrase from the message that triggers this bias>",
      "description": "<one sentence explaining how the attacker exploits this cognitive bias>"
    }
  ],
  "plainEnglish": {
    "tlDr": "<one sentence plain-language verdict: what should the reader do right now?>",
    "whatWeFound": "<2-3 sentences in non-technical language explaining the strongest signals>",
    "whyItMatters": "<1-2 sentences on real-world risk in plain terms>"
  }
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
    //  GOOGLE GEMINI 1.5 FLASH ANALYSIS ENGINE
    // ================================================================
    async function analyzeWithGemini(message, urls, apiKey) {
        const systemPrompt = `You are a Senior Cybersecurity Threat Analyst specializing in Social Engineering, MITRE ATT&CK T1566 (Phishing), BEC (Business Email Compromise), and cognitive psychology.
Analyze the provided message text and list of extracted URLs.

Respond ONLY with a valid, raw JSON object matching this schema (no markdown fences, no explanatory text outside JSON):
{
  "riskScore": <integer 0 to 100>,
  "verdict": "<SAFE | SUSPICIOUS | PHISHING>",
  "techniques": ["<MITRE ATT&CK or Social Engineering technique tag>"],
  "summary": "<2-3 sentence concise threat analysis>",
  "recommendations": ["<Actionable mitigation step 1>", "<Actionable mitigation step 2>", "<Actionable mitigation step 3>"],
  "psychTriggers": [
    {
      "name": "<Psychological tactic exploited, e.g. False Urgency, Authority Impersonation, Fear & Intimidation, Curiosity Bait, Scarcity, Social Proof, Credential Harvesting>",
      "icon": "<single emoji>",
      "severity": "<high | med | low>",
      "quote": "<exact short phrase from the message that triggers this bias>",
      "description": "<one sentence explaining how the attacker exploits this cognitive bias>"
    }
  ],
  "plainEnglish": {
    "tlDr": "<one sentence plain-language verdict>",
    "whatWeFound": "<2-3 sentences in non-technical language>",
    "whyItMatters": "<1-2 sentences on real-world risk>"
  }
}`;

        const userContent = `Message to analyze:\n"""\n${message}\n"""\n\nExtracted URLs found in message:\n${urls.length ? urls.join('\n') : 'None'}`;

        const resp = await fetch(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' + encodeURIComponent(apiKey),
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [
                        { role: 'user', parts: [{ text: systemPrompt + '\n\n' + userContent }] }
                    ],
                    generationConfig: {
                        temperature: 0.1,
                        maxOutputTokens: 2048,
                        responseMimeType: 'application/json'
                    }
                })
            }
        );

        if (!resp.ok) {
            let errText = '';
            try {
                const errData = await resp.json();
                errText = (errData.error && errData.error.message) || resp.statusText;
            } catch (_) {
                errText = await resp.text();
            }
            if (resp.status === 400 && /API key not valid/i.test(errText)) {
                throw new Error('Gemini API Key is invalid. Please check your key.');
            }
            throw new Error(`Gemini API error (${resp.status}): ${errText}`);
        }

        const data = await resp.json();
        const rawContent = data.candidates && data.candidates[0] && data.candidates[0].content &&
            data.candidates[0].content.parts && data.candidates[0].content.parts[0] &&
            data.candidates[0].content.parts[0].text;
        if (!rawContent) throw new Error('Gemini returned an empty response.');

        let jsonText = rawContent.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/g, '').trim();
        return JSON.parse(jsonText);
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
        const isAi = /GPT|Gemini/i.test(engineName);

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

        // ---- Psychological & Cognitive Manipulation Breakdown ----
        if (ai.psychTriggers && ai.psychTriggers.length) {
            html += '<div class="psych-card">'
                +   '<h4>🧠 Social Engineering &amp; Psychological Tactic Breakdown</h4>'
                +   '<div class="psych-triggers-grid">';
            ai.psychTriggers.forEach(function (t) {
                const sev = t.severity || 'med';
                const sevLabel = { high: 'High', med: 'Medium', low: 'Low' }[sev] || 'Medium';
                html += ''
                    + '<div class="psych-trigger-item sev-' + sev + '">'
                    +   '<div class="psych-header-row">'
                    +     '<span class="psych-tactic-name">' + escapeHtml(t.icon ? t.icon + ' ' : '🧠 ') + escapeHtml(t.name || 'Psychological Tactic') + '</span>'
                    +     '<span class="psych-sev-badge">' + sevLabel + '</span>'
                    +   '</div>'
                    +   (t.quote ? '<span class="psych-quote">"' + escapeHtml(t.quote) + '"</span>' : '')
                    +   '<p class="psych-explanation">' + escapeHtml(t.description || '') + '</p>'
                    + '</div>';
            });
            html += '</div></div>';
        }

        // ---- Plain English Explanation ----
        if (ai.plainEnglish) {
            html += '<div class="plain-english-card">'
                +   '<h4>🗣️ Plain-English Explanation <span style="font-size:0.72rem;opacity:.7;font-weight:600;">(zero jargon)</span></h4>'
                +   '<p><strong>In short:</strong> ' + escapeHtml(ai.plainEnglish.tlDr || ai.summary) + '</p>'
                +   (ai.plainEnglish.whatWeFound ? '<p><strong>What we found:</strong> ' + escapeHtml(ai.plainEnglish.whatWeFound) + '</p>' : '')
                +   (ai.plainEnglish.whyItMatters ? '<p><strong>Why it matters:</strong> ' + escapeHtml(ai.plainEnglish.whyItMatters) + '</p>' : '')
                + '</div>';
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
    //  SECURITY AWARENESS LAB (SIMULATOR)
    // ================================================================
    function initSimulator() {
        dom.btnJudgePhish.addEventListener('click', () => judgeSimScenario(true));
        dom.btnJudgeSafe.addEventListener('click',  () => judgeSimScenario(false));
        dom.btnPrevSim.addEventListener('click',    prevSimScenario);
        dom.btnNextSim.addEventListener('click',    nextSimScenario);
        renderSimScenario();
    }

    function renderSimScenario() {
        const s = SIM_SCENARIOS[currentSimIndex];
        if (!s) return;

        dom.simCurrentIndex.textContent = (currentSimIndex + 1) + ' / ' + SIM_SCENARIOS.length;
        dom.simScenarioCategory.textContent = s.category;
        const diffEl = dom.simScenarioDifficulty;
        diffEl.textContent = s.difficulty;
        diffEl.className = 'sim-diff-badge ' + (s.diffClass || 'diff-med');
        dom.simFrom.textContent = s.from;
        dom.simSubject.textContent = s.subject;
        dom.simBody.textContent = s.body;

        // Reset decision UI
        dom.simDecisionArea.classList.remove('hidden');
        dom.simFeedbackArea.classList.add('hidden');
        dom.simFeedbackArea.className = 'sim-feedback-area hidden';
        dom.simFeedbackArea.innerHTML = '';
        dom.btnJudgePhish.disabled = false;
        dom.btnJudgeSafe.disabled  = false;
        dom.btnPrevSim.disabled = (currentSimIndex === 0);
        dom.btnNextSim.disabled = (currentSimIndex === SIM_SCENARIOS.length - 1);
        dom.btnNextSim.textContent = (currentSimIndex === SIM_SCENARIOS.length - 1)
            ? '🏁 Complete Training'
            : 'Next Scenario →';

        updateSimStats();
    }

    function judgeSimScenario(userSaysPhish) {
        const s = SIM_SCENARIOS[currentSimIndex];
        if (!s || dom.btnJudgePhish.disabled) return;

        simStats.attempted++;
        const isCorrect = (userSaysPhish === s.isPhish);
        if (isCorrect) simStats.correct++;

        dom.btnJudgePhish.disabled = true;
        dom.btnJudgeSafe.disabled  = true;
        dom.simDecisionArea.classList.add('hidden');

        const verdictLabel = s.isPhish ? '🚨 PHISHING ATTACK' : '✅ LEGITIMATE COMMUNICATION';
        let headline = isCorrect
            ? '🎯 Correct! Your threat-detection instincts are sharp.'
            : '😬 Not quite — and that is exactly how real attacks win.';

        let breakdown = '';
        if (s.cognitiveBiases && s.cognitiveBiases.length) {
            breakdown += '<div class="feedback-breakdown"><h5>🧠 Psychological levers used:</h5><ul>';
            s.cognitiveBiases.forEach(b => { breakdown += '<li>' + escapeHtml(b) + '</li>'; });
            breakdown += '</ul></div>';
        }
        if (s.indicators && s.indicators.length) {
            breakdown += '<div class="feedback-breakdown"><h5>🔎 ' + (s.isPhish ? 'Red flags' : 'Green flags') + ' to remember:</h5><ul>';
            s.indicators.forEach(i => { breakdown += '<li>' + escapeHtml(i) + '</li>'; });
            breakdown += '</ul></div>';
        }
        if (s.coaching) {
            breakdown += '<div class="feedback-breakdown" style="border-left-color:#00ff9c;"><h5 style="color:#00ff9c;">💡 Coach\'s Tip</h5><p style="font-size:0.84rem;color:#8b949e;line-height:1.5;margin:0;">' + escapeHtml(s.coaching) + '</p></div>';
        }

        dom.simFeedbackArea.className = 'sim-feedback-area ' + (isCorrect ? 'correct' : 'incorrect');
        dom.simFeedbackArea.innerHTML =
              '<div class="feedback-headline">' + headline + '</div>'
            + '<div class="feedback-body"><strong>Correct answer: ' + verdictLabel + '</strong><br>'
            +   escapeHtml(s.explanation || '') + '</div>'
            + breakdown;

        updateSimStats();
    }

    function updateSimStats() {
        const pct = simStats.attempted ? Math.round((simStats.correct / simStats.attempted) * 100) : 0;
        dom.simScore.textContent = pct + '%';
        dom.simScoreRatio.textContent = simStats.correct + ' / ' + simStats.attempted;
    }

    function prevSimScenario() {
        if (currentSimIndex > 0) {
            currentSimIndex--;
            renderSimScenario();
        }
    }

    function nextSimScenario() {
        if (currentSimIndex < SIM_SCENARIOS.length - 1) {
            currentSimIndex++;
            renderSimScenario();
        }
    }

    function resetSimulator() {
        currentSimIndex = 0;
        simStats = { attempted: 0, correct: 0 };
        renderSimScenario();
    }

    // ================================================================
    //  AI-POWERED SCENARIO GENERATOR
    // ================================================================
    function buildScenarioPrompt() {
        return `Create ONE realistic enterprise phishing awareness training scenario that is DIFFERENT from overused classics (no "gift cards for the CEO", no generic password reset, no Nigerian prince).

Choose a modern, realistic lure: invoice fraud, QR-code quishing, vishing follow-up, voicemail phishing, SaaS consent phishing, payroll impersonation, LinkedIn recruiter bait, or a legitimate-but-ambiguous internal email.

Return strictly valid JSON with this exact schema (no markdown fences):
{
  "category": "<attack category, e.g. Invoice Fraud, SaaS Consent Phishing, Vishing, Quishing>",
  "difficulty": "<Easy | Intermediate | Advanced>",
  "from": "<plausible sender address>",
  "subject": "<email subject line>",
  "body": "<full realistic message body, 4-10 sentences, plausible and detailed. EITHER a convincing phish OR a legitimate but subtly ambiguous email>",
  "isPhish": <true or false>,
  "explanation": "<1-2 sentence explanation of verdict>",
  "cognitiveBiases": ["<psychological lever exploited, e.g. Authority Bias, Scarcity, Social Proof, Curiosity>"],
  "indicators": ["<concrete red flags or green flags>"],
  "coaching": "<one actionable coaching tip>"
}`;
    }

    function normalizeGeneratedScenario(json) {
        const d = {};
        d.category    = String(json.category || 'Generated Scenario');
        d.difficulty  = String(json.difficulty || 'Intermediate');
        d.diffClass   = { 'Easy': 'diff-easy', 'Intermediate': 'diff-med', 'Advanced': 'diff-hard' }[d.difficulty] || 'diff-med';
        d.from        = String(json.from || 'Unknown Sender <unknown@example.com>');
        d.subject     = String(json.subject || 'No Subject');
        d.body        = String(json.body || '');
        d.isPhish     = !!json.isPhish;
        d.title       = String(json.title || d.category);
        d.explanation = String(json.explanation || '');
        d.cognitiveBiases = Array.isArray(json.cognitiveBiases) ? json.cognitiveBiases.map(String) : [];
        d.indicators      = Array.isArray(json.indicators) ? json.indicators.map(String) : [];
        d.coaching        = String(json.coaching || '');
        return d;
    }

    async function generateScenarioGemini(apiKey) {
        const resp = await fetch(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' + encodeURIComponent(apiKey),
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ role: 'user', parts: [{ text: buildScenarioPrompt() }] }],
                    generationConfig: { temperature: 0.9, maxOutputTokens: 1600, responseMimeType: 'application/json' }
                })
            }
        );
        if (!resp.ok) {
            let errText = '';
            try { errText = (await resp.json()).error?.message || resp.statusText; } catch (_) { errText = await resp.text(); }
            throw new Error('Gemini generate error (' + resp.status + '): ' + errText);
        }
        const data = await resp.json();
        const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!content) throw new Error('Gemini returned an empty scenario.');
        return JSON.parse(content.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/g, '').trim());
    }

    async function generateScenarioOpenAI(apiKey) {
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: 'You are a security awareness training content designer. Respond ONLY with valid JSON matching the requested schema.' },
                    { role: 'user', content: buildScenarioPrompt() }
                ],
                temperature: 0.9,
                response_format: { type: 'json_object' }
            })
        });
        if (!resp.ok) {
            let errText = '';
            try { errText = (await resp.json()).error?.message || resp.statusText; } catch (_) { errText = await resp.text(); }
            throw new Error('OpenAI generate error (' + resp.status + '): ' + errText);
        }
        const data = await resp.json();
        const content = data.choices?.[0]?.message?.content;
        if (!content) throw new Error('OpenAI returned an empty scenario.');
        return JSON.parse(content);
    }

    async function generateAIScenario() {
        if (!apiKey) {
            dom.simFeedbackArea.className = 'sim-feedback-area incorrect';
            dom.simFeedbackArea.innerHTML =
                  '<div class="feedback-headline">🔑 API Key Required</div>'
                + '<div class="feedback-body">Enter a <strong>Gemini</strong> or <strong>OpenAI</strong> API key in the Analyzer tab, then try again. Or use the built-in scenarios with the offline heuristic engine.</div>';
            dom.simFeedbackArea.classList.remove('hidden');
            return;
        }

        if (!dom.btnGenerateChallenge) return;
        dom.btnGenerateChallenge.disabled = true;
        const originalLabel = dom.btnGenerateChallenge.innerHTML;
        dom.btnGenerateChallenge.innerHTML = '⏳ Generating...';

        try {
            const provider = aiProvider === 'openai' ? 'openai' : 'gemini';
            const raw = provider === 'openai'
                ? await generateScenarioOpenAI(apiKey)
                : await generateScenarioGemini(apiKey);
            const scenario = normalizeGeneratedScenario(raw);
            SIM_SCENARIOS.push(scenario);
            currentSimIndex = SIM_SCENARIOS.length - 1;
            renderSimScenario();

            dom.simFeedbackArea.className = 'sim-feedback-area correct';
            dom.simFeedbackArea.innerHTML =
                  '<div class="feedback-headline">✨ New AI-Generated Challenge Added</div>'
                + '<div class="feedback-body">A fresh <strong>' + escapeHtml(scenario.category) + '</strong> scenario was generated by '
                + (provider === 'openai' ? 'GPT-4o-mini' : 'Gemini 1.5 Flash') + ' — scenario ' + SIM_SCENARIOS.length + ' of ' + SIM_SCENARIOS.length + '. Apply your instincts!</div>';
            dom.simFeedbackArea.classList.remove('hidden');
        } catch (err) {
            console.error('Scenario generation failed:', err);
            dom.simFeedbackArea.className = 'sim-feedback-area incorrect';
            dom.simFeedbackArea.innerHTML =
                  '<div class="feedback-headline">⚠️ Generation Failed</div>'
                + '<div class="feedback-body">' + escapeHtml(err.message || 'Could not generate the scenario.') + '</div>';
            dom.simFeedbackArea.classList.remove('hidden');
        } finally {
            dom.btnGenerateChallenge.disabled = false;
            dom.btnGenerateChallenge.innerHTML = originalLabel;
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
        if (d.analysis.psychTriggers && d.analysis.psychTriggers.length) {
            md += `\n## Psychological Tactics Exploited\n`;
            d.analysis.psychTriggers.forEach(t => {
                md += `- ${t.icon || ''} ${t.name} (${t.severity || 'med'}): ${t.description || ''}\n`;
            });
        }
        if (d.analysis.plainEnglish) {
            md += `\n## Plain-English Summary\n${d.analysis.plainEnglish.tlDr || ''}\n`;
        }
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