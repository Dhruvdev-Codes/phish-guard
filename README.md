# Phish-Guard 🛡️

**AI-Powered Social Engineering Analyzer**

A client-side web application that uses AI to detect phishing and social-engineering attempts in emails, SMS, and other text-based communications. Built as a B.Tech 4th-year Cybersecurity & AI capstone project.

## Live Demo

🔗 **https://dhruvdev-codes.github.io/phish-guard/**

## Features

- **AI-Powered Analysis** — GPT models analyze messages for social-engineering tactics (urgency, authority, fear, impersonation…)
- **URL Reputation Scanning** — VirusTotal integration checks every extracted URL for known threats
- **Risk Scoring** — 0–100 score with color-coded verdicts (safe / suspicious / phishing)
- **Error Handling** — friendly, actionable messages for bad keys, rate limits, and network failures
- **BYOK Security** — your API keys stay in browser memory only; never saved to disk or any server

## Quick Start

1. Open `phish-guard-app/index.html` in your browser (or visit the live demo)
2. Expand **⚙️ API Configuration**
3. Enter your **OpenAI API key** (required)
4. Optionally enter a **VirusTotal API key** to enable URL scanning
5. Paste a suspicious message and click **🔍 Scan for Threats**

## API Keys

| Service | Purpose | Get a Key |
|---------|---------|-----------|
| OpenAI | Phishing text analysis | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |
| VirusTotal | URL reputation (optional) | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |

> ⚠️ **Security:** Keys are held in browser memory only. They are cleared when the page closes and are never transmitted to any server other than the respective API endpoints.

## Architecture

```
phish-guard/
├── index.html          — Page structure & UI (served at root)
├── style.css           — Dark cybersecurity theme
├── app.js              — Core analysis logic
├── README.md           — Project documentation
├── .gitignore          — Git ignore configuration
└── .github/workflows/
    └── pages.yml       — GitHub Actions Pages deployment
```

### How It Works

1. **URL Extraction** — Regex-based extraction of URLs from the pasted message
2. **VirusTotal Scan** — Extracted URLs are submitted to VirusTotal’s API for reputation analysis (via a public CORS proxy)
3. **AI Analysis** — The full message is sent to OpenAI with a structured prompt requesting risk score, detected techniques, summary, and recommendations
4. **Result Rendering** — Color-coded risk badges, technique tags, extracted URLs, and VirusTotal verdicts are rendered

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3, Vanilla JavaScript (ES6+) |
| AI Engine | OpenAI GPT-4o-mini |
| Threat Intel | VirusTotal API v3 |
| Hosting | GitHub Pages |
| Security | BYOK (Bring Your Own Key) |

## Deploying to GitHub Pages

The repository includes a GitHub Actions workflow (`.github/workflows/pages.yml`) that automatically builds and publishes the app to **https://dhruvdev-codes.github.io/phish-guard/** on every push to `main`.

**One-time setup (takes 30 seconds):**

1. Open your repo on GitHub → **Settings**
2. Scroll to **Pages** (left sidebar, under "Code and automation")
3. Under **Build and deployment** → **Source**, select **GitHub Actions**
4. Re-run the workflow (Actions → "Deploy to GitHub Pages" → **Re-run all jobs**) or just push a new commit

The workflow serves the `phish-guard-app/` folder. Every future push to `main` deploys automatically.

## Limitations

- **CORS Proxy:** VirusTotal’s API does not allow direct browser calls, so a public CORS proxy (`corsproxy.io`) is used. A production deployment would route through a backend server.
- **BYOK Model:** Users must supply their own API keys. This keeps keys secure but adds a setup step.
- **URL Limit:** Maximum 5 URLs are scanned per analysis to manage API quota.

## License

Built for academic purposes — B.Tech 4th-Year Cybersecurity & AI Capstone Project.

---

**Author:** [Dhruv](https://github.com/Dhruvdev-Codes)