/**
 * Phish-Guard: Forensic Database & Unified Threat Intelligence Vault Engine
 */
(function () {
    'use strict';

    const DB_NAME = 'PhishGuardVaultDB';
    const DB_VERSION = 1;
    const STORE_NAME = 'forensic_records';
    const LS_KEY = 'phishguard_vault_records_v1';

    let dbInstance = null;
    let inMemoryCache = [];
    let isInitialized = false;

    let currentFilterCategory = 'all';
    let currentFilterVerdict = 'all';
    let currentSearchTerm = '';
    let currentSortOrder = 'newest';

    function openDatabase() {
        return new Promise((resolve) => {
            if (!window.indexedDB) {
                resolve(null);
                return;
            }
            try {
                const request = window.indexedDB.open(DB_NAME, DB_VERSION);
                request.onupgradeneeded = function (e) {
                    const db = e.target.result;
                    if (!db.objectStoreNames.contains(STORE_NAME)) {
                        const s = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
                        s.createIndex('type', 'type', { unique: false });
                        s.createIndex('verdict', 'verdict', { unique: false });
                        s.createIndex('timestamp', 'timestamp', { unique: false });
                    }
                };
                request.onsuccess = function (e) {
                    dbInstance = e.target.result;
                    resolve(dbInstance);
                };
                request.onerror = function () {
                    resolve(null);
                };
            } catch (err) {
                resolve(null);
            }
        });
    }

    function readFromLocalStorage() {
        try {
            const raw = localStorage.getItem(LS_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch (e) { return []; }
    }

    function writeToLocalStorage(records) {
        try {
            localStorage.setItem(LS_KEY, JSON.stringify(records));
        } catch (e) {}
    }

    async function loadAllRecordsFromStore() {
        if (dbInstance) {
            return new Promise((resolve) => {
                try {
                    const tx = dbInstance.transaction(STORE_NAME, 'readonly');
                    const store = tx.objectStore(STORE_NAME);
                    const req = store.getAll();
                    req.onsuccess = () => {
                        inMemoryCache = req.result || [];
                        inMemoryCache.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
                        writeToLocalStorage(inMemoryCache.slice(0, 50));
                        resolve(inMemoryCache);
                    };
                    req.onerror = () => {
                        inMemoryCache = readFromLocalStorage();
                        resolve(inMemoryCache);
                    };
                } catch (e) {
                    inMemoryCache = readFromLocalStorage();
                    resolve(inMemoryCache);
                }
            });
        }
        inMemoryCache = readFromLocalStorage();
        inMemoryCache.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        return inMemoryCache;
    }

    async function persistRecord(record) {
        if (!record.id) {
            record.id = 'rec_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
        }
        if (!record.timestamp) {
            record.timestamp = Date.now();
        }
        if (!record.dateStr) {
            record.dateStr = new Date(record.timestamp).toLocaleString();
        }

        const existingIdx = inMemoryCache.findIndex(r => r.id === record.id);
        if (existingIdx >= 0) {
            inMemoryCache[existingIdx] = record;
        } else {
            inMemoryCache.unshift(record);
        }

        if (dbInstance) {
            return new Promise((resolve) => {
                try {
                    const tx = dbInstance.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    store.put(record);
                    tx.oncomplete = () => {
                        writeToLocalStorage(inMemoryCache.slice(0, 50));
                        resolve(record);
                    };
                    tx.onerror = () => {
                        writeToLocalStorage(inMemoryCache);
                        resolve(record);
                    };
                } catch (e) {
                    writeToLocalStorage(inMemoryCache);
                    resolve(record);
                }
            });
        }
        writeToLocalStorage(inMemoryCache);
        return record;
    }

    async function deleteRecordFromStore(recordId) {
        inMemoryCache = inMemoryCache.filter(r => r.id !== recordId);
        if (dbInstance) {
            return new Promise((resolve) => {
                try {
                    const tx = dbInstance.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    store.delete(recordId);
                    tx.oncomplete = () => {
                        writeToLocalStorage(inMemoryCache.slice(0, 50));
                        resolve(true);
                    };
                    tx.onerror = () => {
                        writeToLocalStorage(inMemoryCache);
                        resolve(true);
                    };
                } catch (e) {
                    writeToLocalStorage(inMemoryCache);
                    resolve(true);
                }
            });
        }
        writeToLocalStorage(inMemoryCache);
        return true;
    }

    async function clearAllRecordsFromStore() {
        inMemoryCache = [];
        writeToLocalStorage([]);
        if (dbInstance) {
            return new Promise((resolve) => {
                try {
                    const tx = dbInstance.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    store.clear();
                    tx.oncomplete = () => resolve(true);
                    tx.onerror = () => resolve(true);
                } catch (e) {
                    resolve(true);
                }
            });
        }
        return true;
    }


    // ================================================================
    //  SAMPLE SEED THREAT DATA
    // ================================================================
    const SAMPLE_SEED_RECORDS = [
        {
            id: "rec_seed_apt29_01",
            type: "scan",
            title: "Nobelium / APT29 Diplomatic Delegation Phishing",
            summary: "Critical Risk (96%) - Advanced OAuth credential harvesting and reverse-proxy MFA bypass targeting foreign affairs staff.",
            riskScore: 96,
            verdict: "MALICIOUS",
            timestamp: Date.now() - (1000 * 60 * 60 * 3),
            dateStr: new Date(Date.now() - (1000 * 60 * 60 * 3)).toLocaleString(),
            tags: ["APT29", "OAuth Bypass", "Spear-Phishing", "Diplomatic", "Urgency"],
            data: {
                message: "URGENT: European Union Summit Security Credentials Update. Your Microsoft 365 delegated application permissions have expired. Verify authentication token immediately: https://usaid-grant-verification.top/token/consent",
                urls: ["https://usaid-grant-verification.top/token/consent", "http://194.26.29.112:8080/payload/invite.iso"],
                analysis: {
                    riskScore: 96,
                    verdict: "MALICIOUS",
                    summary: "High-confidence spear-phishing campaign exploiting authority bias and fake OAuth consent workflows.",
                    psychTriggers: [
                        { name: "Authority Bias", severity: "Critical" },
                        { name: "Artificial Urgency", severity: "High" }
                    ]
                }
            }
        },
        {
            id: "rec_seed_header_02",
            type: "header",
            title: "Executive BEC Spoof - DMARC Fail & Display Deception",
            summary: "Critical Risk (92%) - CEO display name spoofing with failed SPF and DMARC alignment from unauthorized relay IP.",
            riskScore: 92,
            verdict: "MALICIOUS",
            timestamp: Date.now() - (1000 * 60 * 60 * 9),
            dateStr: new Date(Date.now() - (1000 * 60 * 60 * 9)).toLocaleString(),
            tags: ["BEC", "Display Spoofing", "DMARC Fail", "Wire Fraud"],
            data: {
                from: "Sarah Jenkins <ceo-office@company-corp-executives.com>",
                returnPath: "bounce@attacker-relay.net",
                auth: { spf: "FAIL", dkim: "NONE", dmarc: "FAIL", alignment: "Misaligned" },
                riskScore: 92,
                verdict: "MALICIOUS",
                rawHeaderSnippet: "From: Sarah Jenkins <ceo-office@company-corp-executives.com>\nReturn-Path: <bounce@attacker-relay.net>\nAuthentication-Results: dmarc=fail (p=reject)"
            }
        },
        {
            id: "rec_seed_quishing_03",
            type: "quishing",
            title: "HR Payroll Direct Deposit QR Quishing Sandbox",
            summary: "High Risk (86%) - Encoded QR code redirecting through Bitly shortener to EvilProxy AitM phishing portal.",
            riskScore: 86,
            verdict: "MALICIOUS",
            timestamp: Date.now() - (1000 * 60 * 60 * 24),
            dateStr: new Date(Date.now() - (1000 * 60 * 60 * 24)).toLocaleString(),
            tags: ["Quishing", "QR Code", "EvilProxy", "Payroll Bait"],
            data: {
                decodedText: "https://bit.ly/hr-portal-direct-deposit-2024",
                finalUrl: "https://adfs-sso-employee-update.top/login",
                riskScore: 86,
                verdict: "MALICIOUS",
                redirectHops: ["https://bit.ly/hr-portal-direct-deposit-2024", "https://adfs-sso-employee-update.top/login"],
                zeroWidthDetected: false
            }
        },
        {
            id: "rec_seed_radar_04",
            type: "radar",
            title: "Typosquat & IDN Homoglyph: chαse-security[.]com",
            summary: "High Risk (89%) - Cyrillic 'а' substitution targeting Chase Banking customer portals with live MX records.",
            riskScore: 89,
            verdict: "MALICIOUS",
            timestamp: Date.now() - (1000 * 60 * 60 * 36),
            dateStr: new Date(Date.now() - (1000 * 60 * 60 * 36)).toLocaleString(),
            tags: ["IDN Homoglyph", "Punycode", "Banking", "Lookalike"],
            data: {
                baseDomain: "chase.com",
                punycode: "xn--chse-security-e1a.com",
                variantDomain: "chαse-security.com",
                riskScore: 89,
                brandTarget: "Chase Bank"
            }
        }
    ];

    async function seedInitialDataIfEmpty() {
        if (inMemoryCache.length === 0) {
            for (const rec of SAMPLE_SEED_RECORDS) {
                await persistRecord(rec);
            }
        }
    }

    // ================================================================
    //  SEARCH & QUERY ENGINE
    // ================================================================
    function searchRecords(query = '', category = 'all', verdict = 'all', sort = 'newest') {
        let results = [...inMemoryCache];

        if (category && category !== 'all') {
            results = results.filter(r => r.type === category);
        }

        if (verdict && verdict !== 'all') {
            if (verdict === 'malicious') {
                results = results.filter(r => (r.riskScore >= 70 || r.verdict === 'MALICIOUS' || r.verdict === 'CRITICAL'));
            } else if (verdict === 'suspicious') {
                results = results.filter(r => (r.riskScore >= 35 && r.riskScore < 70) || r.verdict === 'SUSPICIOUS');
            } else if (verdict === 'safe') {
                results = results.filter(r => (r.riskScore < 35 || r.verdict === 'SAFE' || r.verdict === 'CLEAN'));
            }
        }

        const q = query.trim().toLowerCase();
        if (q) {
            const terms = q.split(/\s+/).filter(Boolean);
            results = results.filter(rec => {
                const searchableText = [
                    rec.title || '',
                    rec.summary || '',
                    rec.type || '',
                    rec.verdict || '',
                    (rec.tags || []).join(' '),
                    rec.notes || '',
                    JSON.stringify(rec.data || {})
                ].join(' ').toLowerCase();

                return terms.every(term => searchableText.includes(term));
            });
        }

        if (sort === 'newest') {
            results.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        } else if (sort === 'oldest') {
            results.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
        } else if (sort === 'highest_risk') {
            results.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
        } else if (sort === 'lowest_risk') {
            results.sort((a, b) => (a.riskScore || 0) - (b.riskScore || 0));
        }

        return results;
    }

    function computeStats() {
        const total = inMemoryCache.length;
        let maliciousCount = 0;
        let suspiciousCount = 0;
        let safeCount = 0;
        let totalRisk = 0;
        let totalIocs = 0;

        inMemoryCache.forEach(r => {
            const score = r.riskScore || 0;
            totalRisk += score;
            if (score >= 70 || r.verdict === 'MALICIOUS' || r.verdict === 'CRITICAL') {
                maliciousCount++;
            } else if (score >= 35 || r.verdict === 'SUSPICIOUS') {
                suspiciousCount++;
            } else {
                safeCount++;
            }
            if (r.data && r.data.urls) {
                totalIocs += r.data.urls.length;
            } else if (r.data && r.data.iocCount) {
                totalIocs += r.data.iocCount;
            }
        });

        const avgScore = total > 0 ? Math.round(totalRisk / total) : 0;
        return {
            total,
            maliciousCount,
            suspiciousCount,
            safeCount,
            avgScore,
            totalIocs,
            maliciousRatio: total > 0 ? Math.round((maliciousCount / total) * 100) : 0
        };
    }

    function exportSTIXBundle(records) {
        const objects = records.map((rec, idx) => ({
            type: "report",
            spec_version: "2.1",
            id: `report--${rec.id || ('phish-' + idx)}`,
            created: new Date().toISOString(),
            modified: new Date().toISOString(),
            name: rec.title || "Phish-Guard Threat Report",
            description: rec.summary || "",
            published: new Date().toISOString(),
            confidence: rec.riskScore || 80,
            labels: ["phishing", "threat-intel", rec.type || "scan", ...(rec.tags || [])],
            custom_properties: {
                x_phishguard_verdict: rec.verdict || "UNKNOWN",
                x_phishguard_risk_score: rec.riskScore || 0,
                x_phishguard_data: rec.data || {}
            }
        }));

        return JSON.stringify({
            type: "bundle",
            id: `bundle--phishguard-${Date.now()}`,
            objects: objects
        }, null, 2);
    }

    function exportCSVMatrix(records) {
        const headers = ["ID", "Timestamp", "Type", "Title", "Verdict", "RiskScore", "Tags", "Summary"];
        const rows = records.map(r => [
            `"${(r.id || '').replace(/"/g, '""')}"`,
            `"${(r.dateStr || '').replace(/"/g, '""')}"`,
            `"${(r.type || '').replace(/"/g, '""')}"`,
            `"${(r.title || '').replace(/"/g, '""')}"`,
            `"${(r.verdict || '').replace(/"/g, '""')}"`,
            r.riskScore || 0,
            `"${((r.tags || []).join('; ')).replace(/"/g, '""')}"`,
            `"${(r.summary || '').replace(/"/g, '""')}"`
        ]);
        return [headers.join(','), ...rows.map(e => e.join(','))].join('\r\n');
    }

    function downloadFile(content, fileName, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ================================================================
    //  UI RENDERERS FOR VAULT TAB
    // ================================================================
    function getTypeBadgeInfo(type) {
        switch (type) {
            case 'scan':     return { label: 'Threat & Psych Scan', icon: '🔍', color: '#38bdf8' };
            case 'header':   return { label: 'Email Header', icon: '📨', color: '#a855f7' };
            case 'quishing': return { label: 'QR & Deep Link', icon: '📱', color: '#fbbf24' };
            case 'radar':    return { label: 'Typosquat Radar', icon: '🌐', color: '#f0883e' };
            case 'payload':  return { label: 'Payload & Smuggle', icon: '📦', color: '#ff4444' };
            case 'ioc':      return { label: 'IOC Studio & Rules', icon: '🔬', color: '#00ff9c' };
            case 'playbook': return { label: 'SOC IR Playbook', icon: '🛡️', color: '#818cf8' };
            case 'copilot':  return { label: 'Copilot Chat', icon: '🤖', color: '#58a6ff' };
            default:         return { label: 'Forensic Record', icon: '📁', color: '#c9d1d9' };
        }
    }

    function getVerdictBadge(verdict, score) {
        const sc = score || 0;
        let vClass = 'badge-verdict-safe';
        let vText = verdict || (sc >= 70 ? 'MALICIOUS' : sc >= 35 ? 'SUSPICIOUS' : 'SAFE');

        if (sc >= 70 || vText === 'MALICIOUS' || vText === 'CRITICAL') {
            vClass = 'badge-verdict-malicious';
        } else if (sc >= 35 || vText === 'SUSPICIOUS') {
            vClass = 'badge-verdict-suspicious';
        }

        return `<span class="badge-verdict ${vClass}">${vText} (${sc}%)</span>`;
    }

    function renderStatsDashboard() {
        const stats = computeStats();
        const container = document.getElementById('vaultStatsDashboard');
        if (!container) return;

        container.innerHTML = `
            <div class="vault-stat-card">
                <div class="stat-num" style="color: var(--accent-cyan);">${stats.total}</div>
                <div class="stat-label">Total Records</div>
            </div>
            <div class="vault-stat-card">
                <div class="stat-num" style="color: var(--accent-red);">${stats.maliciousCount} (${stats.maliciousRatio}%)</div>
                <div class="stat-label">Malicious Threats</div>
            </div>
            <div class="vault-stat-card">
                <div class="stat-num" style="color: var(--accent-yellow);">${stats.suspiciousCount}</div>
                <div class="stat-label">Suspicious Detections</div>
            </div>
            <div class="vault-stat-card">
                <div class="stat-num" style="color: var(--accent-green);">${stats.totalIocs}</div>
                <div class="stat-label">Threat Indicators</div>
            </div>
            <div class="vault-stat-card">
                <div class="stat-num" style="color: ${stats.avgScore >= 70 ? 'var(--accent-red)' : stats.avgScore >= 35 ? 'var(--accent-yellow)' : 'var(--accent-green)'};">${stats.avgScore}%</div>
                <div class="stat-label">Avg Risk Score</div>
            </div>
        `;
    }

    function renderRecordCards() {
        const container = document.getElementById('vaultRecordsGrid');
        if (!container) return;

        const records = searchRecords(currentSearchTerm, currentFilterCategory, currentFilterVerdict, currentSortOrder);

        const countBadge = document.getElementById('vaultResultsCount');
        if (countBadge) {
            countBadge.textContent = `${records.length} records found`;
        }

        if (records.length === 0) {
            container.innerHTML = `
                <div class="vault-empty-state">
                    <div class="empty-icon">📭</div>
                    <h3>No Forensic Records Match Your Search</h3>
                    <p>Try clearing your keyword, adjusting the filters, or seed sample threat intelligence data.</p>
                    <button type="button" class="btn-vault-action" onclick="window.PhishGuardDB.seedSampleData()">🎲 Seed Sample Threat Archive</button>
                </div>
            `;
            return;
        }

        container.innerHTML = records.map(rec => {
            const badge = getTypeBadgeInfo(rec.type);
            const verdictHtml = getVerdictBadge(rec.verdict, rec.riskScore);
            const tagsHtml = (rec.tags || []).slice(0, 4).map(t => `<span class="vault-tag-pill">${escapeHtml(t)}</span>`).join('');

            return `
                <div class="vault-record-card" data-record-id="${rec.id}">
                    <div class="vault-record-header">
                        <div class="vault-type-badge" style="border: 1px solid ${badge.color}; color: ${badge.color};">
                            <span>${badge.icon}</span> ${badge.label}
                        </div>
                        ${verdictHtml}
                    </div>

                    <h4 class="vault-record-title">${escapeHtml(rec.title || 'Untitled Forensic Record')}</h4>
                    <p class="vault-record-summary">${escapeHtml(rec.summary || 'No summary available.')}</p>

                    <div class="vault-tags-row">
                        ${tagsHtml}
                    </div>

                    <div class="vault-record-footer">
                        <span class="vault-timestamp">🕒 ${escapeHtml(rec.dateStr || new Date(rec.timestamp).toLocaleString())}</span>
                        <div class="vault-card-actions">
                            <button type="button" class="btn-vault-card-action" onclick="window.PhishGuardDB.inspectRecord('${rec.id}')" title="Inspect Dossier">
                                🔍 Inspect
                            </button>
                            <button type="button" class="btn-vault-card-action btn-workbench-load" onclick="window.PhishGuardDB.loadRecordIntoWorkbench('${rec.id}')" title="Load into Tool Workbench">
                                🔄 Load
                            </button>
                            <button type="button" class="btn-vault-card-action btn-ask-copilot" onclick="window.PhishGuardDB.askCopilotAboutRecord('${rec.id}')" title="Ask Copilot">
                                🤖 Copilot
                            </button>
                            <button type="button" class="btn-vault-card-action btn-delete-record" onclick="window.PhishGuardDB.deleteRecord('${rec.id}')" title="Delete">
                                🗑️
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function refreshVaultUI() {
        renderStatsDashboard();
        renderRecordCards();
    }

    // ================================================================
    //  RECORD INSPECTOR & DOSSIER MODAL
    // ================================================================
    function inspectRecord(recordId) {
        const rec = inMemoryCache.find(r => r.id === recordId);
        if (!rec) return;

        let modal = document.getElementById('vaultInspectorModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'vaultInspectorModal';
            modal.className = 'vault-modal-backdrop';
            document.body.appendChild(modal);
        }

        const badge = getTypeBadgeInfo(rec.type);
        const formattedJson = JSON.stringify(rec, null, 2);

        modal.innerHTML = `
            <div class="vault-modal-content">
                <div class="vault-modal-header">
                    <div>
                        <div class="vault-modal-category" style="color: ${badge.color};">
                            ${badge.icon} ${badge.label} &bull; ${rec.dateStr || ''}
                        </div>
                        <h3 class="vault-modal-title">${escapeHtml(rec.title || 'Forensic Record Dossier')}</h3>
                    </div>
                    <button type="button" class="vault-modal-close" onclick="window.PhishGuardDB.closeInspector()">&times;</button>
                </div>

                <div class="vault-modal-body">
                    <div class="vault-modal-metric-bar">
                        <div><strong>Risk Score:</strong> <span style="color: ${rec.riskScore >= 70 ? 'var(--accent-red)' : 'var(--accent-green)'}; font-weight: 700;">${rec.riskScore || 0}%</span></div>
                        <div><strong>Verdict:</strong> <strong>${escapeHtml(rec.verdict || 'N/A')}</strong></div>
                        <div><strong>Record ID:</strong> <code>${escapeHtml(rec.id)}</code></div>
                    </div>

                    <div style="margin-top: 14px;">
                        <label class="card-label">📝 Executive Summary &amp; Findings:</label>
                        <p style="background: rgba(14, 20, 34, 0.6); padding: 12px; border-radius: 8px; border: 1px solid var(--border-subtle); color: var(--text-primary);">
                            ${escapeHtml(rec.summary || 'N/A')}
                        </p>
                    </div>

                    ${rec.tags && rec.tags.length > 0 ? `
                        <div style="margin-top: 14px;">
                            <label class="card-label">🏷️ Forensic Tags:</label>
                            <div class="vault-tags-row">
                                ${rec.tags.map(t => `<span class="vault-tag-pill">${escapeHtml(t)}</span>`).join('')}
                            </div>
                        </div>
                    ` : ''}

                    <div style="margin-top: 16px;">
                        <div class="card-header-flex">
                            <label class="card-label">📦 Raw Forensic Data (STIX / JSON):</label>
                            <button type="button" class="btn-script-copy" onclick="navigator.clipboard.writeText(document.getElementById('rawRecordJsonText').innerText); alert('Record JSON copied!');">📋 Copy JSON</button>
                        </div>
                        <pre class="vault-raw-json"><code id="rawRecordJsonText">${escapeHtml(formattedJson)}</code></pre>
                    </div>
                </div>

                <div class="vault-modal-footer">
                    <button type="button" class="btn-sample" onclick="window.PhishGuardDB.loadRecordIntoWorkbench('${rec.id}')">🔄 Load into Workbench</button>
                    <button type="button" class="btn-sample btn-ask-copilot-inline" onclick="window.PhishGuardDB.askCopilotAboutRecord('${rec.id}')">🤖 Ask Copilot</button>
                    <button type="button" class="btn-link" onclick="window.PhishGuardDB.closeInspector()">Close</button>
                </div>
            </div>
        `;

        modal.classList.add('active');
    }

    function closeInspector() {
        const modal = document.getElementById('vaultInspectorModal');
        if (modal) modal.classList.remove('active');
    }

    function loadRecordIntoWorkbench(recordId) {
        const rec = inMemoryCache.find(r => r.id === recordId);
        if (!rec) return;

        closeInspector();
        closeGlobalSearch();

        const data = rec.data || {};

        switch (rec.type) {
            case 'scan': {
                if (window.PhishGuard && window.PhishGuard.switchToTab) {
                    window.PhishGuard.switchToTab('analyzerTab');
                }
                const msgInput = document.getElementById('messageInput');
                if (msgInput) {
                    msgInput.value = data.message || rec.summary || '';
                    msgInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
                const scanBtn = document.getElementById('scanButton');
                if (scanBtn) setTimeout(() => scanBtn.click(), 300);
                break;
            }
            case 'header': {
                if (window.PhishGuard && window.PhishGuard.switchToTab) {
                    window.PhishGuard.switchToTab('headerTab');
                }
                const hdrInput = document.getElementById('headerInput');
                if (hdrInput) {
                    hdrInput.value = data.rawHeaderSnippet || `From: ${data.from || ''}\nReturn-Path: ${data.returnPath || ''}\nAuthentication-Results: spf=${data.auth?.spf || 'none'} dkim=${data.auth?.dkim || 'none'} dmarc=${data.auth?.dmarc || 'none'}`;
                    hdrInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
                const hdrBtn = document.getElementById('analyzeHeaderBtn');
                if (hdrBtn) setTimeout(() => hdrBtn.click(), 300);
                break;
            }
            case 'quishing': {
                if (window.PhishGuard && window.PhishGuard.switchToTab) {
                    window.PhishGuard.switchToTab('quishingTab');
                }
                const sandboxInput = document.getElementById('urlInput') || document.getElementById('sandboxUrlInput');
                if (sandboxInput) {
                    sandboxInput.value = data.targetUrl || data.decodedText || data.rawUrl || data.finalUrl || '';
                }
                const btnAnalyze = document.getElementById('analyzeUrlBtn');
                if (btnAnalyze) setTimeout(() => btnAnalyze.click(), 300);
                break;
            }
            case 'radar': {
                if (window.PhishGuard && window.PhishGuard.switchToTab) {
                    window.PhishGuard.switchToTab('radarTab');
                }
                const radarInput = document.getElementById('radarDomainInput');
                if (radarInput) {
                    radarInput.value = data.baseDomain || data.brandTarget || 'chase.com';
                }
                const radarBtn = document.getElementById('btnGenerateRadar');
                if (radarBtn) setTimeout(() => radarBtn.click(), 300);
                break;
            }
            case 'payload': {
                if (window.PhishGuard && window.PhishGuard.switchToTab) {
                    window.PhishGuard.switchToTab('payloadTab');
                }
                const payloadInput = document.getElementById('payloadInput');
                if (payloadInput) {
                    payloadInput.value = data.rawPayload || `<script>\n// ${rec.title}\nvar payload = window.atob("...");\nvar blob = new Blob([payload]);\n<\/script>`;
                }
                const payloadBtn = document.getElementById('analyzePayloadBtn');
                if (payloadBtn) setTimeout(() => payloadBtn.click(), 300);
                break;
            }
            case 'ioc': {
                if (window.PhishGuard && window.PhishGuard.switchToTab) {
                    window.PhishGuard.switchToTab('iocTab');
                }
                const iocInput = document.getElementById('iocRawInput') || document.getElementById('iocSearchInput');
                if (iocInput) {
                    iocInput.value = data.rawText || (data.domains ? data.domains.join('\n') : '') || (data.iocs ? JSON.stringify(data.iocs, null, 2) : '') || '';
                }
                const btnExtract = document.getElementById('btnExtractIOCs');
                if (btnExtract && iocInput && iocInput.value) setTimeout(() => btnExtract.click(), 300);
                break;
            }
            case 'playbook': {
                if (window.PhishGuard && window.PhishGuard.switchToTab) {
                    window.PhishGuard.switchToTab('playbookTab');
                }
                break;
            }
            case 'copilot': {
                if (window.PhishGuardCopilot && window.PhishGuardCopilot.askWithContext) {
                    window.PhishGuardCopilot.askWithContext(`Can you explain the forensic investigation for ${rec.title}?`);
                }
                break;
            }
            default: break;
        }
    }

    function askCopilotAboutRecord(recordId) {
        const rec = inMemoryCache.find(r => r.id === recordId);
        if (!rec) return;

        closeInspector();
        closeGlobalSearch();

        const query = `Please provide a thorough SOC threat briefing and remediation analysis for this stored incident:
Title: ${rec.title}
Risk Score: ${rec.riskScore}% (${rec.verdict})
Summary: ${rec.summary}
Tags: ${(rec.tags || []).join(', ')}`;

        if (window.PhishGuardCopilot && window.PhishGuardCopilot.askWithContext) {
            window.PhishGuardCopilot.askWithContext(query, { scan: true, header: true, ioc: true, playbook: true });
        }
    }

    // ================================================================
    //  GLOBAL SPOTLIGHT QUICK-SEARCH (Ctrl+K)
    // ================================================================
    function openGlobalSearch() {
        let modal = document.getElementById('globalSearchModal');
        if (!modal) {
            createGlobalSearchDOM();
            modal = document.getElementById('globalSearchModal');
        }
        modal.classList.add('active');
        const input = document.getElementById('globalSearchInput');
        if (input) {
            input.value = '';
            input.focus();
            renderGlobalSearchResults('');
        }
    }

    function closeGlobalSearch() {
        const modal = document.getElementById('globalSearchModal');
        if (modal) modal.classList.remove('active');
    }

    function createGlobalSearchDOM() {
        const modal = document.createElement('div');
        modal.id = 'globalSearchModal';
        modal.className = 'global-search-backdrop';
        modal.innerHTML = `
            <div class="global-search-container">
                <div class="global-search-input-box">
                    <span class="search-icon">🔍</span>
                    <input type="text" id="globalSearchInput" class="global-search-input" placeholder="Search saved scans, threat indicators, domains, CVEs, or tools (Esc to exit)…" autocomplete="off">
                    <kbd class="search-kbd">Esc</kbd>
                </div>
                <div id="globalSearchResults" class="global-search-results"></div>
                <div class="global-search-footer">
                    <span>Navigation: <kbd>↑</kbd> <kbd>↓</kbd> to cycle &bull; <kbd>Enter</kbd> to inspect &bull; <kbd>Esc</kbd> to close</span>
                    <span>Phish-Guard Forensic Vault</span>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeGlobalSearch();
        });

        const input = document.getElementById('globalSearchInput');
        if (input) {
            input.addEventListener('input', (e) => {
                renderGlobalSearchResults(e.target.value);
            });
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') closeGlobalSearch();
            });
        }
    }

    function renderGlobalSearchResults(term) {
        const container = document.getElementById('globalSearchResults');
        if (!container) return;

        const records = searchRecords(term, 'all', 'all', 'newest').slice(0, 8);

        const toolSuggestions = [
            { name: "Threat & Psych Analyzer", tab: "analyzerTab", icon: "🔍", desc: "Scan email lures for cognitive biases & risk scoring" },
            { name: "Email Header Analyzer", tab: "headerTab", icon: "📨", desc: "Inspect SPF, DKIM, DMARC alignment & hop latency" },
            { name: "QR & Deep Link Sandbox", tab: "quishingTab", icon: "📱", desc: "Analyze quishing codes & sandbox redirect chains" },
            { name: "Lookalike & Typosquat Radar", tab: "radarTab", icon: "🌐", desc: "Scan Punycode and IDN homoglyphs" },
            { name: "Payload & Smuggling Inspector", tab: "payloadTab", icon: "📦", desc: "Deconstruct HTML Smuggling blobs & double extensions" },
            { name: "SOC IR Playbooks", tab: "playbookTab", icon: "🛡️", desc: "Execute NIST/SANS incident containment checklists" },
            { name: "IOC Studio & Detection Rules", tab: "iocTab", icon: "🔬", desc: "Generate YARA, Sigma, KQL & Snort rules" },
            { name: "AI Cyber Copilot", tab: "copilotTab", icon: "🤖", desc: "Live conversational AI cybersecurity assistant" },
            { name: "Threat Vault & Database", tab: "databaseTab", icon: "🗄️", desc: "Search & audit all past session threat intelligence" }
        ].filter(t => !term || t.name.toLowerCase().includes(term.toLowerCase()) || t.desc.toLowerCase().includes(term.toLowerCase()));

        let html = '';

        if (toolSuggestions.length > 0 && (!term || toolSuggestions.length < 8)) {
            html += `<div class="search-category-header">⚙️ Quick Tool Navigation</div>`;
            html += toolSuggestions.slice(0, 3).map(t => `
                <div class="search-result-item" onclick="window.PhishGuard.switchToTab('${t.tab}'); window.PhishGuardDB.closeGlobalSearch();">
                    <span class="search-item-icon">${t.icon}</span>
                    <div class="search-item-text">
                        <div class="search-item-title">${t.name}</div>
                        <div class="search-item-sub">${t.desc}</div>
                    </div>
                    <span class="search-item-action">Jump &rarr;</span>
                </div>
            `).join('');
        }

        if (records.length > 0) {
            html += `<div class="search-category-header">🗄️ Saved Threat Records (${records.length})</div>`;
            html += records.map(rec => {
                const badge = getTypeBadgeInfo(rec.type);
                return `
                    <div class="search-result-item" onclick="window.PhishGuardDB.inspectRecord('${rec.id}'); window.PhishGuardDB.closeGlobalSearch();">
                        <span class="search-item-icon">${badge.icon}</span>
                        <div class="search-item-text">
                            <div class="search-item-title">${escapeHtml(rec.title || 'Record')} <span class="search-score-pill" style="color: ${rec.riskScore >= 70 ? 'var(--accent-red)' : 'var(--accent-green)'};">${rec.riskScore || 0}%</span></div>
                            <div class="search-item-sub">${escapeHtml(rec.summary || '')}</div>
                        </div>
                        <span class="search-item-action">Inspect &rarr;</span>
                    </div>
                `;
            }).join('');
        }

        if (!html) {
            html = `
                <div class="vault-empty-state" style="padding: 24px 12px;">
                    <p style="color: var(--text-dim);">No matching tools or forensic records found for "${escapeHtml(term)}".</p>
                </div>
            `;
        }

        container.innerHTML = html;
    }

    // ================================================================
    //  EVENT BINDINGS & CONTROLLER
    // ================================================================
    function bindVaultEvents() {
        const filterPills = document.querySelectorAll('.vault-filter-pill');
        filterPills.forEach(pill => {
            pill.addEventListener('click', () => {
                filterPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                currentFilterCategory = pill.dataset.filter || 'all';
                renderRecordCards();
            });
        });

        const verdictSelect = document.getElementById('vaultVerdictFilter');
        if (verdictSelect) {
            verdictSelect.addEventListener('change', (e) => {
                currentFilterVerdict = e.target.value;
                renderRecordCards();
            });
        }

        const sortSelect = document.getElementById('vaultSortSelect');
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                currentSortOrder = e.target.value;
                renderRecordCards();
            });
        }

        const searchInput = document.getElementById('vaultSearchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                currentSearchTerm = e.target.value;
                renderRecordCards();
            });
        }

        const btnExportStix = document.getElementById('btnVaultExportSTIX');
        if (btnExportStix) {
            btnExportStix.addEventListener('click', () => {
                const data = searchRecords(currentSearchTerm, currentFilterCategory, currentFilterVerdict, currentSortOrder);
                const stix = exportSTIXBundle(data);
                downloadFile(stix, `phishguard-stix-intel-${Date.now()}.json`, 'application/json');
            });
        }

        const btnExportCsv = document.getElementById('btnVaultExportCSV');
        if (btnExportCsv) {
            btnExportCsv.addEventListener('click', () => {
                const data = searchRecords(currentSearchTerm, currentFilterCategory, currentFilterVerdict, currentSortOrder);
                const csv = exportCSVMatrix(data);
                downloadFile(csv, `phishguard-forensic-matrix-${Date.now()}.csv`, 'text/csv');
            });
        }

        const btnExportBackup = document.getElementById('btnVaultExportBackup');
        if (btnExportBackup) {
            btnExportBackup.addEventListener('click', () => {
                const fullBackup = JSON.stringify({
                    app: "Phish-Guard",
                    version: "2.5",
                    exportedAt: new Date().toISOString(),
                    records: inMemoryCache
                }, null, 2);
                downloadFile(fullBackup, `phishguard-vault-backup-${Date.now()}.json`, 'application/json');
            });
        }

        const fileImportInput = document.getElementById('vaultFileInput');
        const btnImportBackup = document.getElementById('btnVaultImportBackup');
        if (btnImportBackup && fileImportInput) {
            btnImportBackup.addEventListener('click', () => fileImportInput.click());
            fileImportInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = async (evt) => {
                    try {
                        const parsed = JSON.parse(evt.target.result);
                        const recordsToAdd = Array.isArray(parsed) ? parsed : (parsed.records || []);
                        if (recordsToAdd.length === 0) {
                            alert('No valid forensic records found in backup file.');
                            return;
                        }
                        for (const r of recordsToAdd) {
                            await persistRecord(r);
                        }
                        refreshVaultUI();
                        alert(`Successfully imported ${recordsToAdd.length} forensic threat records!`);
                    } catch (err) {
                        alert('Error parsing backup JSON file.');
                    }
                };
                reader.readAsText(file);
                e.target.value = '';
            });
        }

        const btnPurge = document.getElementById('btnVaultPurge');
        if (btnPurge) {
            btnPurge.addEventListener('click', async () => {
                if (confirm('Are you sure you want to purge the Phish-Guard Forensic Database? All saved session scans will be permanently erased.')) {
                    await clearAllRecordsFromStore();
                    refreshVaultUI();
                }
            });
        }

        const btnSeed = document.getElementById('btnVaultSeedArchive');
        if (btnSeed) {
            btnSeed.addEventListener('click', async () => {
                for (const rec of SAMPLE_SEED_RECORDS) {
                    await persistRecord({ ...rec, id: 'rec_seed_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6) });
                }
                refreshVaultUI();
            });
        }

        window.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                openGlobalSearch();
            }
        });

        const btnGlobalSearchTrigger = document.getElementById('btnGlobalSearchTrigger');
        if (btnGlobalSearchTrigger) {
            btnGlobalSearchTrigger.addEventListener('click', openGlobalSearch);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // ================================================================
    //  PUBLIC API
    // ================================================================
    window.PhishGuardDB = {
        init: async function () {
            if (isInitialized) return;
            await openDatabase();
            await loadAllRecordsFromStore();
            await seedInitialDataIfEmpty();
            bindVaultEvents();
            refreshVaultUI();
            isInitialized = true;
        },

        saveRecord: async function (record) {
            const saved = await persistRecord(record);
            refreshVaultUI();
            return saved;
        },

        recordScan: async function (arg1, arg2, arg3) {
            let message = '';
            let analysis = null;
            let urls = [];
            let vtResults = null;
            let engine = '';

            if (arg1 && typeof arg1 === 'object' && arg1.analysis) {
                message = arg1.message || '';
                analysis = arg1.analysis;
                urls = arg1.urls || [];
                vtResults = arg1.vtResults || null;
                engine = arg1.engine || '';
            } else {
                message = arg1 || '';
                analysis = arg2 || null;
                urls = arg3 || [];
            }

            const risk = analysis ? (analysis.riskScore || 0) : 0;
            const verdict = analysis ? (analysis.verdict || 'UNKNOWN') : 'UNKNOWN';
            const psychNames = (analysis && analysis.psychTriggers) ? analysis.psychTriggers.map(p => p.name || p) : [];

            const title = analysis && analysis.summary
                ? `Threat Scan: ${analysis.summary.substring(0, 55)}...`
                : `Threat Scan (${new Date().toLocaleTimeString()})`;

            return window.PhishGuardDB.saveRecord({
                type: 'scan',
                title: title,
                summary: `${verdict} (${risk}%) - ${analysis?.summary || 'Threat scan analyzed.'}`,
                riskScore: risk,
                verdict: verdict,
                tags: [...psychNames, verdict, (urls && urls.length > 0 ? `${urls.length} URLs` : 'No URLs')],
                data: { message, urls, analysis, vtResults, engine }
            });
        },

        recordThreatScan: function (arg1, arg2, arg3) {
            return window.PhishGuardDB.recordScan(arg1, arg2, arg3);
        },

        recordHeaderScan: async function (headerData) {
            const hd = headerData?.data || headerData || {};
            const parsed = hd.parsed || {};
            const auth = hd.auth || {};
            const risk = typeof hd.riskScore === 'number' ? hd.riskScore : (typeof headerData?.riskScore === 'number' ? headerData.riskScore : 0);
            const verdict = hd.verdict || headerData?.verdict || 'UNKNOWN';

            return window.PhishGuardDB.saveRecord({
                type: 'header',
                title: `Email Header: ${parsed.from ? parsed.from.substring(0, 45) : (parsed.subject ? parsed.subject.substring(0, 45) : 'Forensics')}`,
                summary: `${verdict} (${risk}%) - SPF: ${auth.spf || 'N/A'}, DKIM: ${auth.dkim || 'N/A'}, DMARC: ${auth.dmarc || 'N/A'}`,
                riskScore: risk,
                verdict: verdict,
                tags: [`SPF: ${auth.spf || 'NONE'}`, `DMARC: ${auth.dmarc || 'NONE'}`, verdict],
                data: hd
            });
        },

        recordQuishingScan: async function (arg1, arg2, arg3, arg4) {
            let targetUrl = '';
            let riskScore = 0;
            let verdict = 'SAFE';
            let details = {};

            if (arg1 && typeof arg1 === 'object') {
                const hd = arg1.data || arg1;
                targetUrl = hd.normalizedUrl || hd.rawUrl || hd.decodedText || 'URL Sandbox';
                riskScore = typeof hd.riskScore === 'number' ? hd.riskScore : 0;
                verdict = hd.verdict || (riskScore >= 70 ? 'MALICIOUS' : riskScore >= 35 ? 'SUSPICIOUS' : 'SAFE');
                details = hd;
            } else {
                targetUrl = arg1 || 'Payload';
                riskScore = typeof arg2 === 'number' ? arg2 : 0;
                verdict = arg3 || 'UNKNOWN';
                details = arg4 || {};
            }

            return window.PhishGuardDB.saveRecord({
                type: 'quishing',
                title: `QR & Deep Link: ${targetUrl.substring(0, 45)}`,
                summary: `${verdict} (${riskScore}%) - Deep-link analysis of ${targetUrl}`,
                riskScore: riskScore,
                verdict: verdict,
                tags: ["QR Sandbox", "Deep Link", verdict],
                data: { targetUrl, riskScore, verdict, ...details }
            });
        },

        recordUrlScan: function (arg1, arg2, arg3, arg4) {
            return window.PhishGuardDB.recordQuishingScan(arg1, arg2, arg3, arg4);
        },

        recordRadarScan: async function (baseDomain, results) {
            let domain = '';
            let resList = [];
            if (baseDomain && typeof baseDomain === 'object') {
                domain = baseDomain.domain || baseDomain.baseDomain || '';
                resList = baseDomain.results || [];
            } else {
                domain = baseDomain || '';
                resList = results || [];
            }
            const count = resList.length || 0;
            return window.PhishGuardDB.saveRecord({
                type: 'radar',
                title: `Typosquat Radar: ${domain}`,
                summary: `Analyzed brand lookalike permutations (${count} variants generated).`,
                riskScore: 75,
                verdict: 'SUSPICIOUS',
                tags: ["Typosquat", "Punycode", domain],
                data: { baseDomain: domain, results: resList }
            });
        },

        recordPayloadScan: async function (arg1, arg2, arg3, arg4, arg5) {
            let name = 'HTML Smuggling / Dropper Payload';
            let risk = 0;
            let verdict = 'MALICIOUS';
            let evasionMethods = [];
            let raw = '';
            let payloadData = {};

            if (arg1 && typeof arg1 === 'object') {
                risk = typeof arg1.riskScore === 'number' ? arg1.riskScore : 0;
                verdict = arg1.verdict || (risk >= 70 ? 'MALICIOUS' : 'SUSPICIOUS');
                evasionMethods = arg1.findings ? arg1.findings.map(f => f.title) : [];
                raw = arg1.raw || arg1.rawPayload || '';
                name = `Payload Analysis (${arg1.findings?.length || 0} indicators)`;
                payloadData = arg1;
            } else {
                name = arg1 || 'HTML Smuggling Dropper';
                risk = typeof arg2 === 'number' ? arg2 : 0;
                verdict = arg3 || 'UNKNOWN';
                evasionMethods = Array.isArray(arg4) ? arg4 : [];
                raw = arg5 || '';
                payloadData = { payloadName: name, riskScore: risk, verdict, evasionMethods, rawPayload: raw };
            }

            return window.PhishGuardDB.saveRecord({
                type: 'payload',
                title: name,
                summary: `${verdict} (${risk}%) - Detected: ${evasionMethods.slice(0, 3).join(', ') || 'Payload analysis complete.'}`,
                riskScore: risk,
                verdict: verdict,
                tags: ["HTML Smuggling", "Payload", ...evasionMethods.slice(0, 3)],
                data: payloadData
            });
        },

        recordCopilotBriefing: async function (arg1, arg2, arg3) {
            let userQuery = '';
            let botReply = '';
            let engineName = 'Built-in SOC Brain';

            if (arg1 && typeof arg1 === 'object') {
                userQuery = arg1.prompt || arg1.userQuery || '';
                botReply = arg1.response || arg1.botReply || '';
                engineName = arg1.engine || arg1.engineName || 'SOC AI';
            } else {
                userQuery = arg1 || '';
                botReply = arg2 || '';
                engineName = arg3 || 'SOC AI';
            }

            return window.PhishGuardDB.saveRecord({
                type: 'copilot',
                title: `Copilot Triage: ${userQuery.substring(0, 45)}...`,
                summary: botReply.substring(0, 150) + '...',
                riskScore: 50,
                verdict: 'INFORMATIONAL',
                tags: ["Copilot", engineName],
                data: { userQuery, botReply, engineName }
            });
        },

        recordCopilotChat: function (arg1, arg2, arg3) {
            return window.PhishGuardDB.recordCopilotBriefing(arg1, arg2, arg3);
        },

        getAllRecords: () => inMemoryCache,
        searchRecords: searchRecords,
        inspectRecord: inspectRecord,
        closeInspector: closeInspector,
        loadRecordIntoWorkbench: loadRecordIntoWorkbench,
        askCopilotAboutRecord: askCopilotAboutRecord,
        openGlobalSearch: openGlobalSearch,
        closeGlobalSearch: closeGlobalSearch,
        deleteRecord: async function (id) {
            await deleteRecordFromStore(id);
            refreshVaultUI();
        },
        seedSampleData: async function () {
            for (const rec of SAMPLE_SEED_RECORDS) {
                await persistRecord({ ...rec, id: 'rec_seed_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6) });
            }
            refreshVaultUI();
        },
        refreshUI: refreshVaultUI
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => window.PhishGuardDB.init());
    } else {
        window.PhishGuardDB.init();
    }
})();