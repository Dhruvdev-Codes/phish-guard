# Phish-Guard 🛡️

**AI & Cognitive Social Engineering Analyzer & Security Awareness Lab**

A modern client-side cybersecurity web application designed to detect phishing, spear-phishing, smishing, and business email compromise (BEC) attacks, while providing an interactive security awareness training simulator.

## 🌐 Live Application

👉 **[https://dhruvdev-codes.github.io/phish-guard/](https://dhruvdev-codes.github.io/phish-guard/)**

---

## ✨ Key Features

- **Multi-Model Detection Architecture:**
  - 🤖 **Google Gemini 1.5 Flash (Free Tier BYOK):** Fast, high-capacity neural social engineering & cognitive manipulation analysis.
  - 🤖 **OpenAI GPT-4o-mini:** Structured JSON threat modeling & MITRE ATT&CK categorization.
  - ⚡ **Local Cognitive Heuristic Engine (Zero-Key Offline Mode):** Built-in cybersecurity engine analyzing urgency, fear, authority pressure, brand spoofing, IP URLs, and risky TLDs without external API calls.
- **📨 Email Header & Spoofing Inspector:**
  - Full RFC 5322 MIME header parsing directly in browser (Received hops, Authentication-Results, From, Return-Path, DKIM-Signature).
  - SPF alignment & pass/fail/softfail breakdown.
  - DKIM signature presence and integrity checks.
  - DMARC policy compliance & disposition evaluation.
  - Envelope Return-Path vs From display name mismatch and Reply-To hijacking detection.
  - Interactive Relay Route Timeline with originating server IP attribution.
  - Multi-engine AI forensic summary and one-click markdown report export.
- **📱 QR Code ("Quishing") & Deep Link Sandbox:**
  - Client-side pure JS QR barcode image scanner (drag-and-drop, file upload, or clipboard Ctrl+V).
  - IDN Homograph Punycode attack detection (`xn--` lookalike Cyrillic/Greek domain spoofing).
  - IP host obfuscation de-obfuscator (Hex `0x...`, Octal `0...`, Dword integer, raw IPv4).
  - Subdomain stacking and brand squatting analyzer (e.g., `login.microsoftonline.com.attacker.cfd`).
  - Open redirect parameter vulnerability exploit detection (`?url=`, `?next=`, `?redirect=`).
  - Stealth zero-width character injection detection (`\u200B`, `\uFEFF`, soft hyphens).
  - High-risk TLD reputation scoring (`.xyz`, `.top`, `.cfd`, `.click`, `.zip`, `.su`, etc.).
  - Live VirusTotal reputation query & one-click security analyst dossier export.
- **🌐 Brand Lookalike & Typosquat Radar (Preemptive Threat Hunting):**
  - Preemptive adversarial infrastructure discovery across homoglyphs (Cyrillic/Greek IDN replacements), bit-squatting (1-bit memory flip mutations), omission/transposition typos, and abusive phishing TLD swaps (`.top`, `.cfd`, `.xyz`, `.zip`, `.click`).
  - Brand keyword stacking analysis (`login-`, `sso-`, `portal-`, `verify-`, `security-`, `mfa-`, `update-`).
  - Automated risk scoring and tier categorization (Critical / High / Medium / Low).
  - In-browser category filter pills and real-time live domain search.
  - Multi-format exports: Export **DNS/Firewall Blocklists** (`0.0.0.0 <domain>` for Pi-hole, Cloudflare Gateway, pfSense, DNS RPZ), **CSV Threat Intelligence Reports**, or copy domain lists.
  - Multi-Engine **AI Brand Defense Advisory** providing customized Certificate Transparency (CT) monitoring alerts, Google Dorks for phishing kit detection, and SPF/DMARC/BIMI policy enforcement recommendations.
- **📦 Attachment & HTML Smuggling Payload Inspector (Client-Side Evasion Defense):**
  - Forensic deconstruction of client-side evasion techniques: detects **HTML Smuggling** (`Blob()`, `URL.createObjectURL()`, `msSaveOrOpenBlob()`, automatic simulated anchor clicks).
  - Safe Base64 payload de-obfuscation with **Windows PE Executable Signature Detection** (`MZ` / DOS stub identification) and decoded payload sandbox preview.
  - Evasive JavaScript execution detection (`eval(unescape(...))`, dynamic `Function()`, hex string arrays).
  - Full-screen iframe overlays (`100vw`/`100vh`) and credential-stealing form interception triggers.
  - Deceptive double file extension detection (`.pdf.exe`, `.xlsx.vbs`, `.docx.iso`, `.jpg.hta`, `.zip.scr`).
  - Malicious SVG script injection and XSS redirection hooks.
  - Multi-engine AI and Local SOC incident triage summaries with Microsoft Sentinel/Defender KQL threat hunting queries and one-click SOC Markdown Dossier export.
- **🛡️ SOC Incident Response & Remediation Playbooks (NIST SP 800-61 / SANS Aligned):**
  - Interactive containment checklists across 6 critical threat vectors: **Business Email Compromise (BEC)**, **Adversary-in-the-Middle (AitM) MFA Bypass**, **HTML Smuggling & Malware Drops**, **OAuth SaaS Illicit Consent Grants**, **Executive Whaling**, and **Quishing**.
  - Dynamic parameter binding: auto-populates victim users, spoofed senders, bad domains, and phishing subjects into all scripts and communications.
  - **Live Auto-Generated Triage & Remediation CLI Scripts**:
    - **Microsoft 365 / Azure AD PowerShell**: Invalidate session refresh tokens (`Revoke-AzureADUserAllRefreshToken`), audit & delete malicious inbox forwarding rules (`Get-InboxRule`, `Remove-InboxRule`), purge phishing emails across all mailboxes (`New-ComplianceSearchAction -Purge`), and tenant URL blocking.
    - **Google Workspace GAM CLI**: Force account signout, delete external forwarding addresses, and organization-wide email purge.
    - **Microsoft Sentinel & Defender KQL Hunts**: Query `OfficeActivity` for unauthorized rule creation, `SigninLogs` for impossible travel token theft, and `DeviceProcessEvents` for browser child droppers.
    - **Splunk SPL Queries**: Search activity logs for mailbox manipulation and attacker indicators.
  - **Ready-to-Send Incident Broadcast Email Drafter**: One-click internal broadcast notices for company employees and executive leadership.
- **🔬 Cyber Threat Intelligence (CTI) IOC Studio & Detection Engineering Workbench:**
  - Automated universal regex extraction across IPv4/IPv6, FQDNs, URLs, Hashes (SHA-256, SHA-1, MD5), Emails, CVEs, MITRE ATT&CK techniques, Windows Registry keys, and Crypto Wallets (BTC/ETH).
  - One-click **🛡️ Defang / Refang** toggle (`hxxps://`, `[.]`, `[@]`) for safe sharing in tickets and Slack.
  - Multi-format CTI Bundling: **OASIS STIX 2.1 JSON Bundle**, **MISP Event JSON**, **CSV Threat Matrix**, and **RPZ/DNS Blocklist**.
  - Automated Detection Engineering Studio: generates valid **YARA Rules (.yar)**, **Sigma SIEM Rules (.yml)**, **Snort / Suricata IDS Rules (.rules)**, **Microsoft Sentinel / Defender KQL Hunts**, and **Splunk SPL**.
  - Built-in real-world threat dossiers (APT29 Nobelium Spear-Phish, Storm-0558 Cloud AitM, QakBot Malspam ISO, LockBit 3.0 Extortion Lure).

- **🌌 Cyber Defense Animated Threat Mesh & Ambient Atmosphere:**
  - Interactive, canvas-driven dynamic cyber defense nodes (Relays, Honeypot Sensors, and Threat Hubs) connected via proximity-based vector links.
  - Live telemetry packet simulation traveling along active mesh connection vectors.
  - Interactive mouse/touch defense field response.
  - Ambient drifting glow orbs and matrix coordinate grid with hardware-accelerated transforms.
  - Adaptive particle scaling per device, Page Visibility API battery-saving auto-pause, and `@media (prefers-reduced-motion)` compliance.
- **📱 Fully Responsive & Mobile-Optimized:**
  - Modern CSS custom property token system across 12 granular breakpoints (1024px down to 380px).
  - iOS touch zoom fixes (`font-size: 16px` on inputs), touch targets meeting 44–48px standards, and notch/safe-area insets (`env(safe-area-inset-*)`).
- **🧠 Psychological & Cognitive Tactic Breakdown:** Maps deceptive linguistic cues to social engineering manipulation categories (e.g. *False Urgency*, *Authority Impersonation*, *Fear & Intimidation*, *Curiosity Bait*, *Credential Harvesting*) complete with exact quoted triggers and severity ratings.
- **🗣️ Plain-English Summary:** Zero-jargon translation explaining the core threat, exact cues found, and practical real-world impact for non-technical users.
- **🎯 Interactive Security Awareness Lab (Simulator):**
  - Hands-on phishing identification training with instant feedback, psychological breakdown, and red/green flags.
  - ✨ **AI Scenario Generator:** Generates fresh, modern enterprise scenarios (quishing, vishing follow-ups, invoice fraud, SaaS consent phishing) using Gemini or OpenAI.
- **🤖 AI Cyber Copilot & SOC Q&A Workbench:**
  - Interactive cyber advisor capable of explaining complex attack vectors (SPF/DKIM/DMARC alignment, HTML smuggling, AitM session hijacking, IDN homographs, social engineering psychology).
  - Full session context aggregator bridging active scan findings, email headers, extracted IOCs, and IR playbook parameters directly into AI reasoning.
  - Multi-provider support: Google Gemini 1.5 Flash, OpenAI GPT-4o-mini, or zero-key Built-in Offline SOC Knowledge Base.
  - One-click inline deep-dive buttons (`🤖 Ask AI Copilot to Explain`) directly from live scan and header verdict cards.
  - Markdown formatting with syntax-highlighted code blocks, copy actions, and full transcript export.
- **⚡ Quick Test Presets:** One-click presets for Bank Alert Scams, CEO Gift Card BEC, Package Smishing, IT Password Expiry, Payroll Bonus lures, and Clean Meeting Invites.
- **🛡️ MITRE ATT&CK Tagging:** Automated mapping to techniques (`T1566: Phishing`, `T1566.002: Spearphishing Link`, `T1598: Phishing for Information`).
- **🔍 VirusTotal Threat Intelligence:** Live reputation checks for extracted URLs and malicious domains.
- **📊 Incident Report Export:** One-click export to Markdown (`.md`) or structured JSON (`.json`) for incident triage.
- **🔒 Privacy-First BYOK Model:** Zero telemetry. API keys reside exclusively in browser memory and are wiped automatically on tab exit.

---

## 🚀 Quick Start

1. Visit **[https://dhruvdev-codes.github.io/phish-guard/](https://dhruvdev-codes.github.io/phish-guard/)** (or open `index.html` locally).
2. **Analyzer Tab:**
   - Choose one of the **⚡ Quick Test Samples** or paste any email/SMS.
   - Select your provider (**Google Gemini**, **OpenAI**, or **Built-in Heuristic Engine**).
   - Click **🔍 Analyze Threats** to view risk score gauge, psychological breakdown, plain-English summary, and indicators.
3. **Simulator Tab:**
   - Step through the interactive scenarios and decide if each is Phishing or Safe.
   - Click **✨ AI-Generated Challenge** to generate a dynamic modern scenario on the fly.
4. Export reports with **📋 Copy Incident Report** or **📥 Download JSON**.

---

## 🔑 API Configuration (Optional)

| Provider | Purpose | Status | Endpoint |
|---|---|---|---|
| **Built-in Heuristic** | Fast regex & semantic cognitive scoring | Always Active | Local Browser Engine |
| **Google Gemini** | Gemini 1.5 Flash deep NLP reasoning | Free Tier (BYOK) | `generativelanguage.googleapis.com` |
| **OpenAI** | GPT-4o-mini deep NLP reasoning | Optional (BYOK) | `api.openai.com/v1` |
| **VirusTotal** | Real-time URL threat reputation | Optional (BYOK) | `virustotal.com/api/v3` |

> 🔒 **Zero-Persistence Guarantee:** Keys are never stored in `localStorage`, cookies, or sent to any custom server.

---

## 🏛️ Architecture & Project Structure

```
phish-guard/
├── index.html              # Main application UI, multi-tab layout & interactive tools
├── style.css               # Modern responsive cyber design tokens & layout
├── cyber-bg.js             # Canvas threat mesh particle & telemetry packet engine
├── app.js                  # Core heuristic engine, AI BYOK handlers, scanner & tabs
├── ioc-studio.js           # CTI regex extraction, STIX 2.1, Sigma & YARA rule generator
├── playbooks.js            # SOC IR playbooks, containment script generator & drafts
├── README.md               # Project documentation & architecture specifications
├── .github/workflows/
│   └── pages.yml           # Automated CI/CD deployment to GitHub Pages
└── phish-guard-app/        # Production bundle mirror
```

---

## 🛠️ Tech Stack

- **Frontend:** Semantic HTML5, Vanilla CSS3 (Dark Theme), Modern Vanilla JavaScript (ES2022)
- **AI & NLP:** Google Gemini 1.5 Flash & OpenAI GPT-4o-mini with structured JSON output
- **Threat Intelligence:** VirusTotal API v3 (via CORS-enabled proxy)
- **Hosting & CI/CD:** GitHub Actions & GitHub Pages
- **Security:** BYOK Architecture with ephemeral in-memory state

---

## 🛡️ Focus & Research Areas

- **Domain:** Cybersecurity & Applied Artificial Intelligence
- **Focus Areas:** Social Engineering Defense, Cognitive Bias Exploitation, MITRE ATT&CK Framework, Client-side Threat Analysis, Explainable AI Threat Scoring.

---

**Author:** [Dhruv](https://github.com/Dhruvdev-Codes) | [LinkedIn](https://www.linkedin.com/in/dhruv-upadhyay-b7711a216)