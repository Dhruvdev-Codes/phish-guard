/**
 * Phish-Guard: Cyber Threat Intelligence (CTI) IOC Studio & Detection Engineering Workbench
 * Automated IOC Extraction, Defanging/Refanging, STIX 2.1 & MISP Bundling, YARA, Sigma, Snort & KQL Rule Generation
 */

(function () {
    'use strict';

    // ================================================================
    //  THREAT SAMPLES PRESETS
    // ================================================================
    const THREAT_SAMPLES = {
        apt29: {
            title: "APT29 / Nobelium Spear-Phishing Campaign",
            rawText: `REPORT: Targeted Spear-Phishing Campaign by Threat Actor APT29 (Nobelium / Midnight Blizzard)
Date: 2024-11-04 | Severity: HIGH | Category: Credential Theft & OAuth Token Abuse

Executive Summary:
The adversary initiated targeted spear-phishing emails impersonating USAID and European Diplomatic delegations to deliver compromised OAuth applications and reverse-proxy credential lures.

Observed Attack Infrastructure & Indicators:
- Sender Infrastructure: mail-gateway-04.diplomatic-dispatch.org (IP: 185.220.101.45)
- Compromised Sender Account: embassy-relations@diplomatic-dispatch.org
- Attacker Phishing Lures:
    * hxxps://auth-portal.diplomatic-update.cfd/sso/login?ref=eu-summit
    * https://usaid-grant-verification.top/token/consent
    * http://194.26.29.112:8080/payload/invite.iso
- Secondary C2 Domains:
    * c2-relay.azure-telemetry-sync.xyz
    * synchost.evil-apt.su
- Dropped File Hashes (ISO / LNK Dropper):
    * SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    * SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
    * MD5: d41d8cd98f00b204e9800998ecf8427e
- Registry Persistence Mechanism:
    * HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetryUpdater
    * HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command
- Associated MITRE ATT&CK Techniques:
    * T1566.002 (Spearphishing Link)
    * T1566.001 (Spearphishing Attachment)
    * T1078 (Valid Accounts)
    * T1528 (Steal Application Access Token)
- Associated Vulnerability: CVE-2023-38606, CVE-2024-21413`
        },

        storm0558: {
            title: "Storm-0558 AitM & Exchange Online Token Theft",
            rawText: `THREAT BULLETIN: Storm-0558 Reverse-Proxy AitM & Cloud Token Forgery
TLP:AMBER | Threat Actor: Storm-0558 / Silk Typhoon

Adversary Tactics:
Adversaries utilized Evilginx2-based adversary-in-the-middle infrastructure to harvest session cookies and bypass FIDO/SMS MFA.

Extracted Indicators of Compromise:
- Originating Proxy IPs:
    * 45.154.255.89
    * 103.151.125.10
- Phishing & AitM Hostnames:
    * login.microsoftonline.com.auth-cloud-verify.xyz
    * portal.office.com-sso-gateway.top
    * secure-m365-token.cfd
- Target Victims:
    * exec-cfo@global-enterprise.com
    * treasury-lead@energy-grid.org
- Phishing URLs:
    * https://portal.office.com-sso-gateway.top/common/oauth2/authorize?client_id=58198
    * https://login.microsoftonline.com.auth-cloud-verify.xyz/login.srf
- Extracted Payload Hashes:
    * SHA256: a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0
    * SHA1: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c
- MITRE Techniques: T1566.002, T1539, T1110`
        },

        qakbot: {
            title: "QakBot / Black Basta Malspam & Smuggled ISO Dropper",
            rawText: `MALWARE ADVISORY: QakBot (QBot) Email Thread Hijacking & ZIP/ISO Smuggling
Distribution Vector: High-volume malspam hijacking existing corporate email threads with password-protected ZIP attachments.

IOC Artifacts:
- Malicious Sender Domain: billing-update-notification.click
- Sender IP: 198.51.100.203
- Phishing Lures & Redirect URLs:
    * http://billing-update-notification.click/invoices/download.php?id=99281
    * https://sharepoint-secure-doc-gateway.xyz/v/doc_share.iso
- Malicious File Samples:
    * Invoice_October_99281.iso (SHA256: 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce)
    * document.vbs (SHA256: 2c624232cdd221771294dfbb310aca000a0df6ec9b5feb9b65ee961f4f84ab09)
    * payload.dll (MD5: 9e107d9d372bb6826bd81d3542a419d6)
- C2 Communication Endpoints:
    * 185.143.223.12:443
    * 91.240.118.77:2222
- Registry Run Keys:
    * HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\QBotClient
- MITRE Techniques: T1566.001, T1059.005, T1027, T1071.001`
        },

        lockbit: {
            title: "LockBit 3.0 Ransomware Extortion & Phishing Lure",
            rawText: `INCIDENT DOSSIER: LockBit 3.0 / BlackCat Affiliate Phishing & Ransomware Delivery
Threat Group: LockBit Supporter Group | Impact: Enterprise Extortion

Observed Indicators & Infrastructure:
- Attacker Phishing Gateway: secure-hr-benefit-update.top
- Attacker Contact Email: lockbit3-support@decryption-service.onion
- Primary C2 & Exfiltration Hosts:
    * 193.106.191.144
    * mega-sync-backup.xyz
    * https://mega-sync-backup.xyz/upload/stager.bat
- Binary & Script Hashes:
    * lockbit3.exe (SHA256: 5a73e6d5e78297b6e92b3c2e64627b40d4a98402ac3be0c41031d258b3c66f77)
    * stager.bat (MD5: 5d41402abc4b2a76b9719d911017c592)
- Cryptocurrency Ransom Wallet (BTC):
    * bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
    * 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
- Targeted Vulnerability: CVE-2023-4966
- MITRE Techniques: T1566.002, T1486, T1490`
        }
    };

    // Placeholder for next parts — Part 1: Patterns, Defang, Extract
    // ================================================================
    //  IOC EXTRACTOR — regex patterns
    // ================================================================
    const PATTERNS = {
        sha256:   { re: /\b[0-9a-fA-F]{64}\b/g,  type: 'hash',     label: 'SHA-256',   color: '#a78bfa' },
        sha1:     { re: /\b[0-9a-fA-F]{40}\b/g,  type: 'hash',     label: 'SHA-1',     color: '#a78bfa' },
        md5:      { re: /\b[0-9a-fA-F]{32}\b/g,  type: 'hash',     label: 'MD5',       color: '#a78bfa' },
        ipv4:     { re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, type: 'ips', label: 'IPv4', color: '#f97316' },
        url:      { re: /hxxps?:\/\/[^\s"'<>(),\]]+|https?:\/\/[^\s"'<>(),\]]+/gi, type: 'urls', label: 'URL', color: '#38bdf8' },
        fqdn:     { re: /(?<![/@])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|xyz|top|cfd|click|zip|su|onion|io|de|fr|ru|info|biz|me|tv)\b/gi, type: 'domains', label: 'Domain', color: '#34d399' },
        email:    { re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, type: 'emails', label: 'Email', color: '#fb923c' },
        cve:      { re: /CVE-\d{4}-\d{4,7}/gi, type: 'cves', label: 'CVE', color: '#f43f5e' },
        mitre:    { re: /T\d{4}(?:\.\d{3})?/g,   type: 'mitre',    label: 'ATT&CK',    color: '#facc15' },
        registry: { re: /HK(?:EY_)?(?:LOCAL_MACHINE|LM|CURRENT_USER|CU|CLASSES_ROOT|CR|USERS|HU|CURRENT_CONFIG|CC)\\[^\s"'<>]+/gi, type: 'registry', label: 'Registry', color: '#c084fc' },
        btc:      { re: /\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, type: 'crypto', label: 'BTC Wallet', color: '#fbbf24' },
        eth:      { re: /\b0x[a-fA-F0-9]{40}\b/g, type: 'crypto',  label: 'ETH Wallet', color: '#fbbf24' }
    };

    function defang(str) {
        return str
            .replace(/https?:\/\//gi, m => m.replace('http', 'hxxp'))
            .replace(/\./g, '[.]')
            .replace(/@/g, '[@]');
    }
    function refang(str) {
        return str
            .replace(/hxxps?:\/\//gi, m => m.replace('hxxp', 'http'))
            .replace(/\[\.\]/g, '.')
            .replace(/\[@\]/g, '@');
    }

    function extractIOCs(rawText) {
        const results = [];
        const seen = new Set();
        const text = refang(rawText);
        for (const [key, cfg] of Object.entries(PATTERNS)) {
            cfg.re.lastIndex = 0;
            let m;
            while ((m = cfg.re.exec(text)) !== null) {
                const val = m[0];
                const uid = cfg.label + '|' + val.toLowerCase();
                if (!seen.has(uid)) {
                    seen.add(uid);
                    results.push({ value: val, type: cfg.type, label: cfg.label, color: cfg.color, key });
                }
            }
        }
        return results;
    }

    // PART 2 continues below

    // ================================================================
    //  EXPORTS
    // ================================================================
    function makeUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        });
    }

    function buildSTIX(iocs) {
        const ts = new Date().toISOString();
        const sTypeMap = { urls: 'url', ips: 'ipv4-addr', hash: 'file', domains: 'domain-name', emails: 'email-addr', cves: 'vulnerability' };
        const objects = iocs.map(ioc => ({
            type: 'indicator', spec_version: '2.1',
            id: 'indicator--' + makeUUID(),
            created: ts, modified: ts,
            name: '[' + ioc.label + '] ' + ioc.value,
            indicator_types: ['malicious-activity'],
            pattern: "[" + (sTypeMap[ioc.type] || 'indicator') + ":value = '" + ioc.value.replace(/'/g, "\\'") + "']",
            pattern_type: 'stix', valid_from: ts,
            labels: [ioc.type, ioc.label.toLowerCase()]
        }));
        return JSON.stringify({ type: 'bundle', id: 'bundle--' + makeUUID(), spec_version: '2.1', objects }, null, 2);
    }

    function buildMISP(iocs) {
        const atMap = { urls: 'url', ips: 'ip-dst', hash: 'sha256', domains: 'domain', emails: 'email-src', cves: 'vulnerability', mitre: 'mitre-attack-pattern', registry: 'regkey', crypto: 'btc' };
        const catMap = { hash: 'Payload delivery', ips: 'Network activity', urls: 'Network activity', domains: 'Network activity' };
        const attrs = iocs.map(ioc => ({
            type: atMap[ioc.type] || 'other',
            category: catMap[ioc.type] || 'External analysis',
            to_ids: ['ips','urls','hash','domains'].includes(ioc.type),
            value: ioc.value,
            comment: 'Phish-Guard IOC Studio — ' + ioc.label
        }));
        return JSON.stringify({ Event: { info: 'Phish-Guard CTI Export ' + new Date().toISOString(), distribution: 1, threat_level_id: 2, analysis: 2, Attribute: attrs } }, null, 2);
    }

    function buildCSV(iocs) {
        const rows = [['Type','Label','Value (Defanged)','Raw Value']];
        iocs.forEach(ioc => {
            const safe = defang(ioc.value).replace(/"/g, '""');
            rows.push([ioc.type, ioc.label, '"' + safe + '"', '"' + ioc.value.replace(/"/g, '""') + '"']);
        });
        return rows.map(r => r.join(',')).join('\n');
    }

    function buildBlocklist(iocs) {
        const ts = new Date().toISOString();
        const lines = iocs
            .filter(i => i.type === 'domains' || i.type === 'ips')
            .map(i => '0.0.0.0 ' + i.value)
            .join('\n');
        return '# Phish-Guard CTI Blocklist — ' + ts + '\n# Compatible: Pi-hole, Cloudflare Gateway, pfSense DNS, RPZ\n' + (lines || '# No domains or IPs found');
    }

    function download(content, filename, mime) {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([content], { type: mime }));
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { a.remove(); URL.revokeObjectURL(a.href); }, 1000);
    }

    // PART 3 continues below

    // ================================================================
    //  DETECTION RULES
    // ================================================================
    function genYARA(iocs) {
        const hashes = iocs.filter(i => i.type === 'hash').map(i => '        // ' + i.label + ': ' + i.value).join('\n') || '        // No file hashes extracted';
        const urls = iocs.filter(i => i.type === 'domains' || i.type === 'urls').slice(0, 8);
        const strDefs = urls.map((d, i) => '        $s' + (i+1) + ' = "' + d.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '" ascii nocase').join('\n') || '        $placeholder = "phishing-domain[.]top" ascii';
        return `rule PhishGuard_CTI_IOC_Hunt
{
    meta:
        description = "Auto-generated detection rule from Phish-Guard CTI IOC Studio"
        author      = "Phish-Guard Detection Engineering"
        date        = "${new Date().toISOString().slice(0,10)}"
        reference   = "https://github.com/Dhruvdev-Codes/phish-guard"

    /* Known Malicious File Hashes:
${hashes}
    */

    strings:
${strDefs}

    condition:
        any of them
}`;
    }

    function genSigma(iocs) {
        const domains = iocs.filter(i => i.type === 'domains').map(i => "            - '" + i.value + "'").join('\n') || "            - 'phishing-domain.xyz'";
        const ips = iocs.filter(i => i.type === 'ips').map(i => "            - '" + i.value + "'").join('\n') || "            - '127.0.0.1'";
        return `title: Phish-Guard CTI IOC Threat Hunt
id: phishguard-cti-${Date.now()}
status: experimental
description: Generated Sigma detection for indicators extracted in Phish-Guard
author: Phish-Guard Detection Engineering
date: ${new Date().toISOString().slice(0,10)}
tags:
    - attack.initial_access
    - attack.t1566
logsource:
    category: proxy
    product: any
detection:
    suspicious_domains:
        cs-host|contains:
${domains}
    suspicious_ips:
        dst_ip|contains:
${ips}
    condition: suspicious_domains or suspicious_ips
falsepositives:
    - Legitimate traffic matching domains
level: high`;
    }

    function genSnort(iocs) {
        const rules = [];
        iocs.filter(i => i.type === 'ips').forEach((ioc, idx) => {
            rules.push(`alert tcp any any -> ${ioc.value} any (msg:"PhishGuard CTI C2 IP [${ioc.value}]"; sid:${9100000 + idx}; rev:1; classtype:trojan-activity;)`);
        });
        iocs.filter(i => i.type === 'domains' || i.type === 'urls').slice(0, 10).forEach((ioc, idx) => {
            const clean = ioc.value.replace(/"/g, '\\"');
            rules.push(`alert http any any -> any any (msg:"PhishGuard CTI Domain [${clean}]"; content:"${clean}"; http_header; nocase; sid:${9101000 + idx}; rev:1; classtype:trojan-activity;)`);
        });
        return rules.length ? `# Phish-Guard Snort / Suricata IDS Rules\n# Generated: ${new Date().toISOString()}\n\n` + rules.join('\n') : `# No network indicators available\n# Paste threat intelligence report to generate IDS rules`;
    }

    function genKQL(iocs) {
        const ips = iocs.filter(i => i.type === 'ips').map(i => '"' + i.value + '"').join(', ') || '"0.0.0.0"';
        const domains = iocs.filter(i => i.type === 'domains').map(i => '"' + i.value + '"').join(', ') || '"phishing-domain.xyz"';
        const hashes = iocs.filter(i => i.type === 'hash').map(i => '"' + i.value + '"').join(', ') || '""';
        return `// Phish-Guard CTI IOC Hunt — Microsoft Sentinel & Defender XDR
// Generated: ${new Date().toISOString()}
let threat_ips = dynamic([${ips}]);
let threat_domains = dynamic([${domains}]);
let threat_hashes = dynamic([${hashes}]);

// 1. Inbound/Outbound connections to adversary IPs
DeviceNetworkEvents
| where RemoteIP in (threat_ips)
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc

// 2. DNS Queries / HTTP Requests to threat domains
DeviceNetworkEvents
| where RemoteUrl has_any (threat_domains)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName

// 3. Process Execution of known file hashes
DeviceFileEvents
| where SHA256 in~ (threat_hashes) or MD5 in~ (threat_hashes)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`;
    }

    function genSplunk(iocs) {
        const ips = iocs.filter(i => i.type === 'ips').map(i => '"' + i.value + '"').join(' OR dest_ip=') || '"0.0.0.0"';
        const domains = iocs.filter(i => i.type === 'domains').map(i => '"' + i.value + '"').join('" OR query="') || '"phishing-domain.xyz"';
        return `\`Comment("Phish-Guard CTI IOC Threat Hunt — Splunk SPL")\`
\`Comment("Generated: ${new Date().toISOString()}")\`

index=firewall OR index=proxy
(dest_ip=${ips} OR query="${domains}")
| table _time src_ip dest_ip dest_port query action bytes
| sort -_time

index=endpoint sourcetype=sysmon EventCode=1
| search CommandLine IN (${domains})
| table _time ComputerName User CommandLine ParentCommandLine`;
    }

    // PART 4 continues below

    // ================================================================
    //  STATE & RENDERING
    // ================================================================
    let _allIOCs = [];
    let _defanged = true;
    let _activeFilter = 'all';
    let _activeRule = 'yara';

    function renderGrid(iocs) {
        const grid = document.getElementById('iocItemsGrid');
        if (!grid) return;
        const search = (document.getElementById('iocSearchInput') || {}).value || '';
        const q = search.toLowerCase();
        const filtered = iocs.filter(ioc => {
            const matchFilter = _activeFilter === 'all' || ioc.type === _activeFilter || (ioc.key && ioc.key === _activeFilter);
            const matchSearch = !q || ioc.value.toLowerCase().includes(q) || ioc.label.toLowerCase().includes(q);
            return matchFilter && matchSearch;
        });
        if (!filtered.length) {
            grid.innerHTML = '<div class="ioc-empty-msg">🔍 No indicators matched. Paste threat intelligence data or select a preset and click <strong>Extract Indicators</strong>.</div>';
            return;
        }
        grid.innerHTML = filtered.map(ioc => {
            const display = _defanged ? defang(ioc.value) : ioc.value;
            return '<div class="ioc-card-item" data-type="' + ioc.type + '">'
                + '<div class="ioc-card-header">'
                + '<span class="ioc-type-badge" style="background:' + ioc.color + '22;color:' + ioc.color + ';border:1px solid ' + ioc.color + '55">' + ioc.label + '</span>'
                + '<button type="button" class="btn-ioc-copy-item" data-val="' + ioc.value.replace(/"/g,'&quot;') + '">📋 Copy</button>'
                + '</div>'
                + '<div class="ioc-card-val">' + display.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>'
                + '<div class="ioc-card-meta">Category: ' + ioc.type + '</div>'
                + '</div>';
        }).join('');
        grid.querySelectorAll('.btn-ioc-copy-item').forEach(btn => {
            btn.addEventListener('click', () => {
                navigator.clipboard.writeText(btn.dataset.val).then(() => {
                    btn.textContent = '✅ Copied';
                    setTimeout(() => { btn.textContent = '📋 Copy'; }, 1500);
                });
            });
        });
    }

    function updateStats(iocs) {
        const counts = { total: iocs.length, domains: 0, ips: 0, urls: 0, hashes: 0, emails: 0 };
        iocs.forEach(i => {
            if (i.type === 'domains') counts.domains++;
            else if (i.type === 'ips') counts.ips++;
            else if (i.type === 'urls') counts.urls++;
            else if (i.type === 'hash') counts.hashes++;
            else if (i.type === 'emails') counts.emails++;
        });
        const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
        setVal('statIocTotal', counts.total);
        setVal('statIocDomains', counts.domains);
        setVal('statIocIps', counts.ips);
        setVal('statIocUrls', counts.urls);
        setVal('statIocHashes', counts.hashes);
        setVal('statIocEmails', counts.emails);
    }

    function renderRule(iocs, ruleType) {
        const block = document.getElementById('iocRuleCodeBlock');
        const title = document.getElementById('iocRuleTitle');
        if (!block) return;
        const titles = { yara: 'YARA Signature Rule (.yar)', sigma: 'Sigma SIEM Detection Rule (.yml)', snort: 'Snort / Suricata IDS Rules (.rules)', kql: 'Microsoft Sentinel / Defender KQL Hunt', splunk: 'Splunk SPL Threat Hunt Query' };
        const gens = { yara: genYARA, sigma: genSigma, snort: genSnort, kql: genKQL, splunk: genSplunk };
        if (title) title.textContent = titles[ruleType] || '';
        block.textContent = (gens[ruleType] || genYARA)(iocs);
    }

    // ================================================================
    //  INIT — wire all DOM events
    // ================================================================
    document.addEventListener('DOMContentLoaded', () => {

        // Threat preset buttons
        const presetBtns = document.querySelectorAll('.btn-ioc-sample, [data-ioc-preset]');
        presetBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const key = btn.dataset.sample || btn.dataset.iocPreset;
                const sample = THREAT_SAMPLES[key];
                if (!sample) return;
                const ta = document.getElementById('iocRawInput');
                if (ta) ta.value = sample.rawText;
                presetBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            });
        });

        // Clear
        const clearBtn = document.getElementById('btnClearIOCInput');
        if (clearBtn) clearBtn.addEventListener('click', () => {
            const ta = document.getElementById('iocRawInput');
            if (ta) ta.value = '';
            _allIOCs = [];
            renderGrid([]);
            updateStats([]);
            renderRule([], _activeRule);
            presetBtns.forEach(b => b.classList.remove('active'));
        });

        // Extract
        const extractBtn = document.getElementById('btnExtractIOCs');
        if (extractBtn) extractBtn.addEventListener('click', () => {
            const ta = document.getElementById('iocRawInput');
            const raw = ta ? ta.value.trim() : '';
            if (!raw) { alert('Please paste threat data or load a preset first.'); return; }
            _allIOCs = extractIOCs(raw);
            renderGrid(_allIOCs);
            updateStats(_allIOCs);
            renderRule(_allIOCs, _activeRule);
        });

        // Defang toggle
        const defangBtn = document.getElementById('toggleDefangBtn');
        if (defangBtn) defangBtn.addEventListener('click', () => {
            _defanged = !_defanged;
            defangBtn.classList.toggle('active', _defanged);
            defangBtn.textContent = _defanged ? '🛡️ Defanged View (Safe)' : '🔓 Refanged View (Live)';
            renderGrid(_allIOCs);
        });

        // Filter pills
        document.querySelectorAll('.ioc-filter-pill').forEach(pill => {
            pill.addEventListener('click', () => {
                document.querySelectorAll('.ioc-filter-pill').forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                _activeFilter = pill.dataset.filter;
                renderGrid(_allIOCs);
            });
        });

        // Search
        const searchInput = document.getElementById('iocSearchInput');
        if (searchInput) searchInput.addEventListener('input', () => renderGrid(_allIOCs));

        // STIX export
        const stixBtn = document.getElementById('btnExportSTIX');
        if (stixBtn) stixBtn.addEventListener('click', () => {
            if (!_allIOCs.length) { alert('Extract IOCs first.'); return; }
            download(buildSTIX(_allIOCs), 'phishguard-iocs.stix.json', 'application/json');
        });

        // MISP export
        const mispBtn = document.getElementById('btnExportMISP');
        if (mispBtn) mispBtn.addEventListener('click', () => {
            if (!_allIOCs.length) { alert('Extract IOCs first.'); return; }
            download(buildMISP(_allIOCs), 'phishguard-iocs.misp.json', 'application/json');
        });

        // CSV export
        const csvBtn = document.getElementById('btnExportCSV');
        if (csvBtn) csvBtn.addEventListener('click', () => {
            if (!_allIOCs.length) { alert('Extract IOCs first.'); return; }
            download(buildCSV(_allIOCs), 'phishguard-iocs.csv', 'text/csv');
        });

        // Blocklist export
        const blBtn = document.getElementById('btnExportBlocklist');
        if (blBtn) blBtn.addEventListener('click', () => {
            if (!_allIOCs.length) { alert('Extract IOCs first.'); return; }
            download(buildBlocklist(_allIOCs), 'phishguard-blocklist.txt', 'text/plain');
        });

        // Rule tabs
        document.querySelectorAll('.btn-ioc-rule-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.btn-ioc-rule-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                _activeRule = tab.dataset.rule;
                renderRule(_allIOCs, _activeRule);
            });
        });

        // Copy rule
        const copyRuleBtn = document.getElementById('btnCopyDetectionRule');
        if (copyRuleBtn) copyRuleBtn.addEventListener('click', () => {
            const block = document.getElementById('iocRuleCodeBlock');
            if (!block || !block.textContent) return;
            navigator.clipboard.writeText(block.textContent).then(() => {
                copyRuleBtn.textContent = '✅ Copied!';
                setTimeout(() => { copyRuleBtn.textContent = '📋 Copy Detection Rule'; }, 1800);
            });
        });

        // Initial empty render
        renderGrid([]);
        renderRule([], _activeRule);
    });

})();
