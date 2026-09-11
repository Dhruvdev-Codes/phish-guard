# Phish-Guard 🛡️

**AI & Heuristic Social Engineering Analyzer**

A modern client-side cybersecurity web application designed to detect phishing, spear-phishing, smishing, and business email compromise (BEC) attacks. Built as a B.Tech 4th-year Cybersecurity & AI capstone project.

## 🌐 Live Application

👉 **[https://dhruvdev-codes.github.io/phish-guard/](https://dhruvdev-codes.github.io/phish-guard/)**

---

## ✨ Key Features

- **Dual-Engine Detection Architecture:**
  - 🤖 **Neural AI Engine (OpenAI GPT-4o-mini):** Deep semantic and social-engineering reasoning, MITRE ATT&CK technique categorization.
  - ⚡ **Local Heuristic Engine (Offline / Zero-API-Key Mode):** Built-in rule-based cybersecurity engine detecting urgency patterns, fear appeals, IP-based URLs, brand spoofing, and abused high-risk TLDs immediately without requiring an API key.
- **⚡ Quick Test Samples:** One-click presets for Bank Alert Scams, CEO Gift Card BEC, Package Smishing, IT Password Expiry, and Clean Meeting Invites for instant demonstration.
- **🛡️ MITRE ATT&CK & Tactic Tagging:** Automatic mapping to MITRE ATT&CK (e.g. `T1566: Phishing`, `T1566.002: Spearphishing Link`, `T1598: Phishing for Information`).
- **🔍 VirusTotal Threat Intelligence:** Live reputation scanning for extracted URLs and malicious domains.
- **📊 Incident Report Export:** One-click export to Markdown (`.md`) or structured JSON (`.json`) for incident triage and documentation.
- **🔒 Privacy-First BYOK Model:** Zero telemetry. API keys reside exclusively in browser memory and are wiped automatically on tab exit.

---

## 🚀 Quick Start

1. Visit **[https://dhruvdev-codes.github.io/phish-guard/](https://dhruvdev-codes.github.io/phish-guard/)** (or open `index.html` locally).
2. Choose one of the **⚡ Quick Test Samples** or paste your own message.
3. Click **🔍 Analyze Threats**.
   - *Default (No Key):* Runs the instantaneous Local Heuristic Engine.
   - *Optional:* Click **⚙️ API Configuration** to enter an OpenAI or VirusTotal key for deep AI analysis.
4. Review the risk score gauge, detected tactics, extracted URLs, and recommended mitigation actions.
5. Click **📋 Copy Incident Report** or **📥 Download JSON** to save findings.

---

## 🔑 API Configuration (Optional)

| Provider | Purpose | Status | Endpoint |
|---|---|---|---|
| **Built-in Heuristic** | Fast regex & semantic indicator scoring | Always Active | Local Browser Engine |
| **OpenAI** | GPT-4o-mini deep NLP threat reasoning | Optional (BYOK) | `api.openai.com/v1` |
| **VirusTotal** | Real-time URL threat reputation | Optional (BYOK) | `virustotal.com/api/v3` |

> 🔒 **Zero-Persistence Guarantee:** Keys are never stored in `localStorage`, cookies, or sent to any custom server.

---

## 🏛️ Architecture & Project Structure

```
phish-guard/
├── index.html              # Main application UI & sample selector
├── style.css               # Cybersecurity dark theme & responsive UI
├── app.js                  # Dual-engine analysis, heuristics, API handlers
├── README.md               # Project documentation & capstone specifications
├── .github/workflows/
│   └── pages.yml           # Automated CI/CD deployment to GitHub Pages
└── phish-guard-app/        # Production bundle mirror
```

---

## 🛠️ Tech Stack

- **Frontend:** Semantic HTML5, Vanilla CSS3 (Custom Dark Cyberpunk Theme), Modern Vanilla JavaScript (ES2022)
- **AI & NLP:** OpenAI GPT-4o-mini Chat Completions API with structured JSON output
- **Threat Intelligence:** VirusTotal API v3 (via CORS-enabled proxy)
- **Hosting & CI/CD:** GitHub Actions & GitHub Pages
- **Security:** BYOK Architecture with ephemeral in-memory state

---

## 🎓 Academic Capstone Context

- **Degree:** Bachelor of Technology (B.Tech) - 4th Year
- **Domain:** Cybersecurity & Applied Artificial Intelligence
- **Focus Areas:** Social Engineering Defense, MITRE ATT&CK Framework, Client-side Threat Analysis, Explainable Threat Scoring.

---

**Author:** [Dhruv](https://github.com/Dhruvdev-Codes)