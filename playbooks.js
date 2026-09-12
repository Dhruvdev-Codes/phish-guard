/**
 * Phish-Guard: SOC Incident Response & Remediation Playbooks Module
 * Aligned with NIST SP 800-61 / SANS Incident Handling Framework
 */

(function () {
    'use strict';

    const PLAYBOOK_DATA = {};
    PLAYBOOK_DATA.bec = {
        title: "Business Email Compromise (BEC) & Financial Diversion",
        icon: "🔴",
        severity: "CRITICAL",
        sla: "15 Min (Immediate Containment)",
        summary: "Adversary has compromised or spoofed corporate mailboxes to intercept invoices, alter wire details, or covertly forward internal financial communications.",
        phases: [
            {
                name: "Phase 1: Triage & Identification",
                items: [
                    { id: "bec-1", text: "Identify affected user accounts, originating sender IP, and message tracking headers.", hint: "Check Message-ID and Authentication-Results headers for spoofing." },
                    { id: "bec-2", text: "Audit mailbox forwarding rules, hidden inbox filters, and delegated permissions.", hint: "Attackers frequently create rules forwarding to external webmail." },
                    { id: "bec-3", text: "Check M365 / Google Workspace Sign-In audit logs for impossible travel or foreign IP access.", hint: "Look for non-compliant device sign-ins or unfamiliar User-Agents." }
                ]
            },
            {
                name: "Phase 2: Immediate Containment & Isolation",
                items: [
                    { id: "bec-4", text: "Revoke all active Azure AD / Google Workspace refresh tokens and session cookies.", hint: "Forces immediate disconnect across all web, desktop, and mobile clients." },
                    { id: "bec-5", text: "Disable external auto-forwarding on the compromised mailbox.", hint: "Remove DeliverToMailboxAndForward and ForwardingSmtpAddress values." },
                    { id: "bec-6", text: "Block attacker sender domain and originating IP on email gateway & perimeter firewall.", hint: "Add to Tenant Allow/Block List (TABL) or perimeter RPZ DNS." }
                ]
            },
            {
                name: "Phase 3: Eradication",
                items: [
                    { id: "bec-7", text: "Execute compliance purge to hard-delete phishing messages from all organization inboxes.", hint: "Run Exchange New-ComplianceSearchAction with -Purge flag." },
                    { id: "bec-8", text: "Remove unauthorized inbox rules (e.g., rules moving finance emails to hidden folders).", hint: "Audit via Get-InboxRule cmdlet." }
                ]
            },
            {
                name: "Phase 4: Recovery & Hardening",
                items: [
                    { id: "bec-9", text: "Reset account password and enforce FIDO2 / WebAuthn phishing-resistant MFA.", hint: "Disable legacy SMS/voice call MFA methods." },
                    { id: "bec-10", text: "Notify finance and accounting teams to halt any pending wire transfers or vendor changes.", hint: "Mandate verbal confirmation over out-of-band known numbers." }
                ]
            },
            {
                name: "Phase 5: Post-Incident & Compliance",
                items: [
                    { id: "bec-11", text: "File formal IC3 / law enforcement report if financial funds were wired.", hint: "Engage banking fraud desk within 24 hours for financial recall." },
                    { id: "bec-12", text: "Conduct post-mortem briefing and update internal anti-spoofing mail flow rules.", hint: "Review DMARC p=reject enforcement status." }
                ]
            }
        ],
        scripts: {
            powershell: (p) => `# 1. Revoke User Refresh Tokens & Active Sessions\nRevoke-AzureADUserAllRefreshToken -ObjectId "${p.victimUser}"\n\n# 2. Check and Remove Malicious Inbox Forwarding Rules\nGet-InboxRule -Mailbox "${p.victimUser}" | Where-Object { $_.ForwardTo -ne $null } | Remove-InboxRule -Confirm:$false\n\n# 3. Disable Mailbox Forwarding Settings\nSet-Mailbox -Identity "${p.victimUser}" -DeliverToMailboxAndForward $false -ForwardingSmtpAddress $null\n\n# 4. Search and Hard-Delete Phishing Messages Across All Mailboxes\n$Search = New-ComplianceSearch -Name "Purge_BEC" -ExchangeLocation All -ContentMatchQuery 'Subject:"${p.phishSubject}" OR From:"${p.attackerSender}"'\nStart-ComplianceSearch -Identity $Search.Name\nStart-Sleep -Seconds 15\nNew-ComplianceSearchAction -SearchName $Search.Name -Purge -PurgeType HardDelete -Confirm:$false\n\n# 5. Add Malicious Domain to Tenant Blocklist\nNew-TenantAllowBlockListItems -EntryType Url -Block -Entries "${p.maliciousDomain}" -Notes "BEC Incident Triage"`,
            gam: (p) => `# 1. Force Signout and Revoke All Sessions\ngam user ${p.victimUser} signout\n\n# 2. Delete External Forwarding\ngam user ${p.victimUser} delete forwardingaddress\n\n# 3. Purge Phishing Emails Across Organization\ngam all users delete messages query "from:${p.attackerSender} OR subject:\\"${p.phishSubject}\\"" doit`,
            kql: (p) => `// Sentinel KQL: Detect Mailbox Rule Modifications\nOfficeActivity\n| where TimeGenerated >= ago(7d)\n| where UserId =~ "${p.victimUser}" and Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")\n| project TimeGenerated, UserId, Operation, ClientIP, Parameters`,
            splunk: (p) => `index=o365 sourcetype="o365:management:activity" (UserId="${p.victimUser}" AND Operation="*InboxRule*") OR (From="${p.attackerSender}")\n| table _time, UserId, Operation, ClientIP, Parameters, Subject`
        },
        broadcast: (p) => `URGENT SECURITY NOTICE: High-Priority BEC / Wire Fraud Attempt\n\nDear Team,\n\nOur SOC has intercepted a targeted Business Email Compromise (BEC) attack attempting to impersonate executive leadership.\n\nThreat Details:\n- Spoofed Sender: ${p.attackerSender}\n- Lure Subject: "${p.phishSubject}"\n- Target / Vector: Unauthorized wire transfer diversion\n\nMandatory Actions:\n1. Do NOT reply or act on wire transfer requests without verbal out-of-band phone verification.\n2. If you received or interacted with this message, report it immediately to the SOC.\n\nSecurity Operations Center (SOC)`
    };

    PLAYBOOK_DATA.aitm = {
        title: "Credential Harvesting & Adversary-in-the-Middle (AitM)",
        icon: "🟠",
        severity: "CRITICAL",
        sla: "20 Minutes",
        summary: "Attacker deployed a reverse-proxy (e.g. Evilginx, Modlishka) to steal victim passwords and session cookies, bypassing traditional MFA prompts in real-time.",
        phases: [
            {
                name: "Phase 1: Triage & Identification",
                items: [
                    { id: "aitm-1", text: "Identify reverse-proxy landing domain and reverse IP lookup.", hint: "AitM proxies mirror Microsoft/Google login pages." },
                    { id: "aitm-2", text: "Extract session authentication token timestamps from Azure AD sign-in logs.", hint: "Look for anomalous User-Agent or ASN mismatches between MFA claim and subsequent token use." }
                ]
            },
            {
                name: "Phase 2: Immediate Containment",
                items: [
                    { id: "aitm-3", text: "Revoke all Azure AD / Google Workspace user session cookies immediately.", hint: "Invalidates the stolen session cookie held by the proxy server." },
                    { id: "aitm-4", text: "Block the reverse-proxy domain on DNS blocklist and firewall.", hint: "Prevents further credential proxying across internal network." }
                ]
            },
            {
                name: "Phase 3: Eradication & Remediation",
                items: [
                    { id: "aitm-5", text: "Purge the phishing lure emails across tenant mailboxes.", hint: "Hard-delete email using Exchange Compliance Search." },
                    { id: "aitm-6", text: "Audit recently registered MFA authentication methods.", hint: "Check Azure AD Authentication Methods for suspicious device enrollments." }
                ]
            },
            {
                name: "Phase 4: Recovery & Hardening",
                items: [
                    { id: "aitm-7", text: "Enforce FIDO2 / WebAuthn Passkeys or Certificate-Based Authentication.", hint: "FIDO2 binds to the origin domain, rendering AitM reverse proxies completely ineffective." }
                ]
            },
            {
                name: "Phase 5: Post-Incident",
                items: [
                    { id: "aitm-8", text: "Document IOCs in Threat Intel repository and conduct user security debrief.", hint: "Educate users on recognizing proxy domain URLs." }
                ]
            }
        ],
        scripts: {
            powershell: (p) => `# 1. Invalidate Compromised Session Tokens\nRevoke-AzureADUserAllRefreshToken -ObjectId "${p.victimUser}"\n\n# 2. Block Malicious Reverse-Proxy URL at Tenant Level\nNew-TenantAllowBlockListItems -EntryType Url -Block -Entries "${p.maliciousDomain}" -Notes "AitM Proxy Defense"\n\n# 3. Purge Phishing Emails Across All Mailboxes\n$Search = New-ComplianceSearch -Name "Purge_AitM" -ExchangeLocation All -ContentMatchQuery 'Subject:"${p.phishSubject}" OR "${p.maliciousDomain}"'\nStart-ComplianceSearch -Identity $Search.Name\nStart-Sleep -Seconds 15\nNew-ComplianceSearchAction -SearchName $Search.Name -Purge -PurgeType HardDelete -Confirm:$false`,
            gam: (p) => `# Force signout of all active sessions\ngam user ${p.victimUser} signout\ngam all users delete messages query "url:\\"${p.maliciousDomain}\\" OR subject:\\"${p.phishSubject}\\"" doit`,
            kql: (p) => `// Detect Anomalous Token Use (AitM Session Cookie Hijacking)\nSigninLogs\n| where TimeGenerated >= ago(2d)\n| where UserPrincipalName =~ "${p.victimUser}"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, AuthenticationRequirement, ConditionalAccessStatus\n| order by TimeGenerated desc`,
            splunk: (p) => `index=azure_ad sourcetype="azure:aad:signin" UserPrincipalName="${p.victimUser}"\n| table _time, IPAddress, Location, AppDisplayName, Status, AuthenticationDetails`
        },
        broadcast: (p) => `SECURITY ALERT: Credential Phishing & Fake Login Page\n\nDear Team,\n\nA deceptive login page mimicking our corporate sign-in portal has been identified.\n\nThreat Indicators:\n- Fake Portal URL: ${p.maliciousDomain}\n- Phishing Subject: "${p.phishSubject}"\n\nPlease note that our authentic corporate login will NEVER be hosted on third-party domains. If you submitted your password on this link, reset your credentials immediately and contact the SOC.\n\nSecurity Operations Center (SOC)`
    };

    PLAYBOOK_DATA.smuggling = {
        title: "HTML Smuggling & In-Memory Malware Dropper",
        icon: "🟡",
        severity: "HIGH",
        sla: "30 Minutes",
        summary: "Attacker delivered an attachment (.html/.svg) that dynamically constructs a malicious payload (.iso, .vbs, .exe) in browser memory via JavaScript Blobs.",
        phases: [
            {
                name: "Phase 1: Triage & Identification",
                items: [
                    { id: "smug-1", text: "Extract dropped filename, SHA-256 hash, and payload decompression mechanisms.", hint: "Inspect browser download history and local temp directories." },
                    { id: "smug-2", text: "Identify endpoints where the attachment was opened.", hint: "Check EDR telemetry for browser process spawning child script processes." }
                ]
            },
            {
                name: "Phase 2: Immediate Containment",
                items: [
                    { id: "smug-3", text: "Isolate affected endpoints from network via EDR (Defender / CrowdStrike).", hint: "Prevents lateral movement and C2 beaconing." },
                    { id: "smug-4", text: "Block payload C2 domain / IP on egress firewall.", hint: "Add domain to perimeter blocklist." }
                ]
            },
            {
                name: "Phase 3: Eradication",
                items: [
                    { id: "smug-5", text: "Purge dropped binary files from local disk and registry autorun keys.", hint: "Inspect %TEMP%, %APPDATA%, and Downloads folders." },
                    { id: "smug-6", text: "Delete phishing emails across all tenant mailboxes.", hint: "Run tenant compliance hard-delete." }
                ]
            },
            {
                name: "Phase 4: Recovery & Validation",
                items: [
                    { id: "smug-7", text: "Perform full EDR forensic scan on target endpoint before lifting isolation.", hint: "Ensure no persistent services or scheduled tasks remain." }
                ]
            },
            {
                name: "Phase 5: Post-Incident",
                items: [
                    { id: "smug-8", text: "Implement mail gateway rule blocking .html/.htm attachments containing JavaScript Blobs.", hint: "Configure Exchange Transport Rule to disallow uninspected HTML wrappers." }
                ]
            }
        ],
        scripts: {
            powershell: (p) => `# 1. Scan and Purge Malicious HTML Attachment Across Inboxes\n$Search = New-ComplianceSearch -Name "Purge_Smuggling" -ExchangeLocation All -ContentMatchQuery 'Subject:"${p.phishSubject}" OR AttachmentNames:".html"'\nStart-ComplianceSearch -Identity $Search.Name\nStart-Sleep -Seconds 15\nNew-ComplianceSearchAction -SearchName $Search.Name -Purge -PurgeType HardDelete -Confirm:$false\n\n# 2. Block Payload Distribution URL\nNew-TenantAllowBlockListItems -EntryType Url -Block -Entries "${p.maliciousDomain}" -Notes "HTML Smuggling Vector"`,
            gam: (p) => `# Purge emails with dangerous HTML attachments\ngam all users delete messages query "has:attachment filename:(.html OR .svg) subject:\\"${p.phishSubject}\\"" doit`,
            kql: (p) => `// EDR Hunting Query: Browser Spawning Script Interpreters\nDeviceProcessEvents\n| where TimeGenerated >= ago(3d)\n| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe")\n| where FileName in~ ("wscript.exe", "cscript.exe", "powershell.exe", "cmd.exe", "mshta.exe")\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName`,
            splunk: (p) => `index=edr (parent_process="chrome.exe" OR parent_process="msedge.exe") (process="wscript.exe" OR process="powershell.exe")\n| table _time, host, user, parent_process, process`
        },
        broadcast: (p) => `WARNING: Malicious Attachment Lure (HTML Smuggling)\n\nDear Team,\n\nOur security monitoring has intercepted a deceptive email containing a dangerous HTML attachment designed to execute scripts when opened.\n\nThreat Details:\n- Subject: "${p.phishSubject}"\n- Sender: ${p.attackerSender}\n\nAction Required:\nDo NOT open attachments from unfamiliar communications. If opened, disconnect your device and contact IT Security.\n\nSecurity Operations Center (SOC)`
    };

    PLAYBOOK_DATA.oauth = {
        title: "OAuth SaaS Illicit Consent Grant Phishing",
        icon: "🟣",
        severity: "CRITICAL",
        sla: "25 Minutes",
        summary: "Victim was tricked into authorizing a malicious SaaS OAuth app with delegated Microsoft Graph permissions (e.g. Mail.Read, Files.ReadWrite.All).",
        phases: [
            {
                name: "Phase 1: Triage & Identification",
                items: [
                    { id: "oauth-1", text: "Identify App ID, Publisher, and delegated scopes of the rogue OAuth app.", hint: "Check Azure AD Enterprise Applications & Consent audit logs." },
                    { id: "oauth-2", text: "Determine all users who granted consent to the malicious application.", hint: "Run Get-AzureADUserOAuth2PermissionGrant across the tenant." }
                ]
            },
            {
                name: "Phase 2: Immediate Containment",
                items: [
                    { id: "oauth-3", text: "Revoke all user consent grants for the malicious App ID.", hint: "Instantly terminates the app's ability to read emails or files via API tokens." },
                    { id: "oauth-4", text: "Disable the Enterprise Application service principal in Azure AD.", hint: "Sets -AccountEnabled $false on the application." }
                ]
            },
            {
                name: "Phase 3: Eradication & Hardening",
                items: [
                    { id: "oauth-5", text: "Permanently delete the malicious Service Principal from Azure AD.", hint: "Remove-AzureADServicePrincipal cmdlet." },
                    { id: "oauth-6", text: "Configure Admin Consent Workflow in Azure AD to block unverified user consent grants.", hint: "Mandates IT admin review before users can authorize third-party apps." }
                ]
            }
        ],
        scripts: {
            powershell: (p) => `# 1. Audit and Revoke OAuth Permissions for Affected User\nGet-AzureADUserOAuth2PermissionGrant -All $true | Where-Object { $_.PrincipalId -eq "${p.victimUser}" } | Remove-AzureADOAuth2PermissionGrant\n\n# 2. Search and Disable Suspicious Service Principals\nGet-AzureADServicePrincipal -All $true | Where-Object { $_.PublisherName -match "Unknown" -or $_.Homepage -match "${p.maliciousDomain}" } | Set-AzureADServicePrincipal -AccountEnabled $false`,
            gam: (p) => `# Audit and revoke third-party Google Marketplace apps\ngam user ${p.victimUser} print tokens\ngam user ${p.victimUser} delete tokens app <AppId>`,
            kql: (p) => `// Hunt for Illicit OAuth Consent Grants\nAuditLogs\n| where TimeGenerated >= ago(7d)\n| where OperationName in ("Consent to application", "Add delegated permission grant")\n| project TimeGenerated, OperationName, TargetResources, InitiatedBy`,
            splunk: (p) => `index=azure_ad sourcetype="azure:aad:audit" OperationName="*Consent to application*"\n| table _time, InitiatedBy, TargetResources`
        },
        broadcast: (p) => `SECURITY ALERT: Unauthorized App Authorization Lure\n\nDear Team,\n\nWe have detected a phishing campaign requesting authorization for an unauthorized third-party application.\n\nThreat Vector:\n- Phishing Subject: "${p.phishSubject}"\n- Attack Method: Fake "Accept Permissions" prompt\n\nAction:\nNever authorize unknown applications requesting access to your corporate inbox. If you consented, contact the SOC immediately.\n\nSecurity Operations Center (SOC)`
    };

    PLAYBOOK_DATA.whaling = {
        title: "Executive Whaling & Display Name Spoofing",
        icon: "🔵",
        severity: "MEDIUM-HIGH",
        sla: "30 Minutes",
        summary: "Attacker created a free webmail account with an executive's display name, attempting to pressure employees into urgent gift card purchases or wire secrecy.",
        phases: [
            {
                name: "Phase 1: Triage & Identification",
                items: [
                    { id: "wh-1", text: "Verify that internal executive accounts were NOT compromised.", hint: "Confirm email originated from external IP and free webmail provider." },
                    { id: "wh-2", text: "Identify all employees who received the display name lure.", hint: "Run message trace for the external sender address." }
                ]
            },
            {
                name: "Phase 2: Immediate Containment",
                items: [
                    { id: "wh-3", text: "Purge the whaling emails from all recipient inboxes.", hint: "Execute tenant compliance hard-delete." },
                    { id: "wh-4", text: "Block attacker external email address on tenant blocklist.", hint: "Add attacker address to blocked senders." }
                ]
            },
            {
                name: "Phase 3: Policy Enforcement",
                items: [
                    { id: "wh-5", text: "Update Exchange Mail Flow anti-spoofing rule for VIP display names.", hint: "Prepend warning banner [EXTERNAL VIP SPOOF] when external sender name matches leadership." }
                ]
            }
        ],
        scripts: {
            powershell: (p) => `# 1. Purge Whaling Message Across All Mailboxes\n$Search = New-ComplianceSearch -Name "Purge_Whaling" -ExchangeLocation All -ContentMatchQuery 'Subject:"${p.phishSubject}" OR From:"${p.attackerSender}"'\nStart-ComplianceSearch -Identity $Search.Name\nStart-Sleep -Seconds 15\nNew-ComplianceSearchAction -SearchName $Search.Name -Purge -PurgeType HardDelete -Confirm:$false\n\n# 2. Block External Attacker Address\nNew-TenantAllowBlockListItems -EntryType Email -Block -Entries "${p.attackerSender}" -Notes "Whaling Impersonation"`,
            gam: (p) => `# Purge whaling message from all users\ngam all users delete messages query "from:${p.attackerSender}" doit`,
            kql: (p) => `// Detect Display Name Impersonation\nEmailEvents\n| where TimeGenerated >= ago(7d)\n| where SenderFromAddress =~ "${p.attackerSender}" or Subject has "${p.phishSubject}"\n| project TimeGenerated, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject`,
            splunk: (p) => `index=email sourcetype="exchange:messagetrace" Sender="${p.attackerSender}"\n| table _time, Sender, Recipient, Subject, Status`
        },
        broadcast: (p) => `FRAUD ADVISORY: Executive Impersonation / Gift Card Scam\n\nDear Team,\n\nAn external threat actor is sending emails pretending to be company leadership requesting assistance with gift cards.\n\nKey Facts:\n- Attacker Address: ${p.attackerSender}\n- Lure Subject: "${p.phishSubject}"\n\nReminder:\nCompany executives will NEVER ask employees to purchase gift cards or bypass financial protocols.\n\nSecurity Operations Center (SOC)`
    };

    PLAYBOOK_DATA.quishing = {
        title: "Quishing / Mobile QR Code Lure Response",
        icon: "🟢",
        severity: "HIGH",
        sla: "25 Minutes",
        summary: "Phishing lure embedded a QR code image to circumvent email security filters and shift victim interaction onto personal mobile devices.",
        phases: [
            {
                name: "Phase 1: Triage & Identification",
                items: [
                    { id: "qu-1", text: "Extract decoded QR destination URL using Phish-Guard QR Sandbox.", hint: "Decode homoglyphs and hidden redirection parameters." },
                    { id: "qu-2", text: "Identify users who scanned the code and submitted credentials on mobile.", hint: "Review MDM / Intune logs and cloud sign-ins from mobile browsers." }
                ]
            },
            {
                name: "Phase 2: Immediate Containment",
                items: [
                    { id: "qu-3", text: "Revoke sessions and reset passwords for affected users.", hint: "Terminate active refresh tokens." },
                    { id: "qu-4", text: "Block QR destination domain on corporate DNS / ZTNA gateway.", hint: "Add domain to perimeter DNS RPZ." }
                ]
            },
            {
                name: "Phase 3: Eradication & Hardening",
                items: [
                    { id: "qu-5", text: "Purge QR email lures from all tenant mailboxes.", hint: "Hard-delete messages matching subject or image attachment." },
                    { id: "qu-6", text: "Deploy Microsoft Defender for Office 365 QR image OCR inspection.", hint: "Enable automated barcode parsing on email ingress." }
                ]
            }
        ],
        scripts: {
            powershell: (p) => `# 1. Revoke Compromised Mobile / Cloud Sessions\nRevoke-AzureADUserAllRefreshToken -ObjectId "${p.victimUser}"\n\n# 2. Block Quishing Destination Domain\nNew-TenantAllowBlockListItems -EntryType Url -Block -Entries "${p.maliciousDomain}" -Notes "Quishing Destination Domain"\n\n# 3. Purge Quishing Emails\n$Search = New-ComplianceSearch -Name "Purge_Quishing" -ExchangeLocation All -ContentMatchQuery 'Subject:"${p.phishSubject}" OR "${p.maliciousDomain}"'\nStart-ComplianceSearch -Identity $Search.Name\nStart-Sleep -Seconds 15\nNew-ComplianceSearchAction -SearchName $Search.Name -Purge -PurgeType HardDelete -Confirm:$false`,
            gam: (p) => `# Delete quishing emails\ngam all users delete messages query "subject:\\"${p.phishSubject}\\"" doit`,
            kql: (p) => `// Detect Mobile Device Cloud Sign-ins\nSigninLogs\n| where TimeGenerated >= ago(2d)\n| where UserPrincipalName =~ "${p.victimUser}"\n| where DeviceDetail.operatingSystem in ("iOS", "Android")\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName`,
            splunk: (p) => `index=azure_ad sourcetype="azure:aad:signin" UserPrincipalName="${p.victimUser}" (DeviceOperatingSystem="iOS" OR DeviceOperatingSystem="Android")\n| table _time, IPAddress, Location, Status`
        },
        broadcast: (p) => `SECURITY WARNING: QR Code Phishing ("Quishing") Alert\n\nDear Team,\n\nPhishing emails containing embedded QR codes are currently targeting our organization.\n\nThreat Subject: "${p.phishSubject}"\nDestination URL: ${p.maliciousDomain}\n\nWarning:\nNever scan QR codes from unexpected emails using your mobile phone. Corporate authentication will never require scanning an unverified email QR barcode.\n\nSecurity Operations Center (SOC)`
    };

    // ================================================================
    //  ENGINE & UI CONTROLLER
    // ================================================================
    let currentScenario = 'bec';
    let currentScript = 'powershell';
    const checklistState = {};

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function getParams() {
        const getVal = (id, def) => {
            const el = document.getElementById(id);
            return (el && el.value.trim()) ? el.value.trim() : def;
        };
        return {
            victimUser: getVal('pbVictimUser', 'victim@company.com'),
            attackerSender: getVal('pbAttackerSender', 'attacker@bad-domain.top'),
            maliciousDomain: getVal('pbMaliciousDomain', 'https://bad-domain.top/auth'),
            phishSubject: getVal('pbPhishSubject', 'URGENT: Executive Wire Transfer Authorization #9921')
        };
    }

    function initPlaybooks() {
        const container = document.getElementById('playbookContainer');
        if (!container) return;

        const btns = document.querySelectorAll('.btn-playbook-select');
        btns.forEach(btn => {
            btn.addEventListener('click', () => {
                btns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentScenario = btn.dataset.scenario || 'bec';
                renderPlaybook();
            });
        });

        const inputs = ['pbVictimUser', 'pbAttackerSender', 'pbMaliciousDomain', 'pbPhishSubject'];
        inputs.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('input', updateScriptsAndBroadcast);
        });

        const resetBtn = document.getElementById('resetPlaybookParamsBtn');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                const s = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
                s('pbVictimUser', 'alex.taylor@company.com');
                s('pbAttackerSender', 'ceo-direct@executive-payroll-corp.top');
                s('pbMaliciousDomain', 'https://login-auth-portal.cfd/auth');
                s('pbPhishSubject', 'URGENT: Executive Wire Transfer Authorization #9921');
                updateScriptsAndBroadcast();
            });
        }

        renderPlaybook();
    }
    window.initPlaybooks = initPlaybooks;

    function renderPlaybook() {
        const container = document.getElementById('playbookContainer');
        if (!container) return;
        const pb = PLAYBOOK_DATA[currentScenario];
        if (!pb) return;

        let totalItems = 0;
        let completedItems = 0;
        pb.phases.forEach(phase => {
            phase.items.forEach(item => {
                totalItems++;
                if (checklistState[item.id]) completedItems++;
            });
        });
        const progressPct = totalItems > 0 ? Math.round((completedItems / totalItems) * 100) : 0;

        let html = `
        <div class="playbook-progress-card">
            <div class="playbook-progress-header">
                <span>🛡️ ${pb.icon} <strong>${pb.title}</strong></span>
                <span>Response SLA: <strong>${pb.sla}</strong> | Checklist: <span id="pbProgressText">${completedItems}/${totalItems} (${progressPct}%)</span></span>
            </div>
            <div class="playbook-progress-bar">
                <div class="playbook-progress-fill" id="pbProgressBarFill" style="width: ${progressPct}%"></div>
            </div>
            <p style="font-size:0.84rem; color:#94a3b8; margin: 4px 0 0 0;">${escapeHtml(pb.summary)}</p>
        </div>`;

        // Render NIST Phases
        pb.phases.forEach(phase => {
            html += `
            <div class="playbook-phase-card">
                <div class="playbook-phase-title">
                    <span>${phase.name}</span>
                </div>
                <div class="playbook-checklist">`;
            phase.items.forEach(item => {
                const isChecked = !!checklistState[item.id];
                html += `
                    <label class="playbook-check-item ${isChecked ? 'completed' : ''}" data-id="${item.id}">
                        <input type="checkbox" class="playbook-check-input" ${isChecked ? 'checked' : ''} data-id="${item.id}">
                        <div>
                            <div class="playbook-check-text">${escapeHtml(item.text)}</div>
                            <div class="playbook-check-hint">💡 ${escapeHtml(item.hint)}</div>
                        </div>
                    </label>`;
            });
            html += `</div></div>`;
        });

        // Render Remediation CLI Scripts
        html += `
        <div class="card">
            <div class="card-header-flex">
                <label class="card-label">💻 Automated Triage &amp; Containment Scripts</label>
                <div class="playbook-script-nav">
                    <button type="button" class="btn-script-tab ${currentScript === 'powershell' ? 'active' : ''}" data-tab="powershell">M365 PowerShell</button>
                    <button type="button" class="btn-script-tab ${currentScript === 'gam' ? 'active' : ''}" data-tab="gam">Google GAM CLI</button>
                    <button type="button" class="btn-script-tab ${currentScript === 'kql' ? 'active' : ''}" data-tab="kql">Sentinel KQL</button>
                    <button type="button" class="btn-script-tab ${currentScript === 'splunk' ? 'active' : ''}" data-tab="splunk">Splunk SPL</button>
                </div>
            </div>
            <div class="payload-code-viewer">
                <div class="payload-code-header">
                    <span id="pbScriptTabTitle">${currentScript.toUpperCase()} Script</span>
                    <button type="button" id="btnCopyPbScript" class="btn-link">📋 Copy Script</button>
                </div>
                <pre class="payload-code-body" id="pbScriptCodeBlock"></pre>
            </div>
        </div>`;

        // Render Executive Broadcast Alert Drafter
        html += `
        <div class="card">
            <div class="card-header-flex">
                <label class="card-label">📢 Internal Incident Broadcast &amp; Alert Drafter</label>
                <button type="button" id="btnCopyPbBroadcast" class="btn-link">📋 Copy Notification</button>
            </div>
            <div class="payload-code-viewer">
                <div class="payload-code-header">
                    <span>Ready-to-Send Security Operations Notice</span>
                </div>
                <pre class="payload-code-body" id="pbBroadcastCodeBlock" style="color:#e2e8f0;"></pre>
            </div>
            <div style="margin-top: 14px;">
                <button type="button" class="btn-ask-copilot-inline" id="btnAskCopilotPlaybook" style="width: 100%; justify-content: center; padding: 10px 16px;">
                    🤖 Ask AI Copilot: Incident Commander Guidance for ${escapeHtml(pb.title)}
                </button>
            </div>
        </div>`;

        container.innerHTML = html;
        attachEvents();
        updateScriptsAndBroadcast();
    }
    function attachEvents() {
        const container = document.getElementById('playbookContainer');
        if (!container) return;

        const checkInputs = container.querySelectorAll('.playbook-check-input');
        checkInputs.forEach(input => {
            input.addEventListener('change', (e) => {
                const id = e.target.dataset.id;
                checklistState[id] = e.target.checked;
                const parentLabel = e.target.closest('.playbook-check-item');
                if (parentLabel) parentLabel.classList.toggle('completed', e.target.checked);
                updateProgress();
            });
        });

        const scriptTabs = container.querySelectorAll('.btn-script-tab');
        scriptTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                scriptTabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                currentScript = tab.dataset.tab;
                updateScriptsAndBroadcast();
            });
        });

        const btnCopyScript = container.querySelector('#btnCopyPbScript');
        if (btnCopyScript) {
            btnCopyScript.addEventListener('click', () => {
                const codeBlock = container.querySelector('#pbScriptCodeBlock');
                if (codeBlock) {
                    navigator.clipboard.writeText(codeBlock.innerText).then(() => {
                        const orig = btnCopyScript.innerText;
                        btnCopyScript.innerText = '✅ Copied!';
                        setTimeout(() => { btnCopyScript.innerText = orig; }, 1800);
                    });
                }
            });
        }

        const btnCopyBroadcast = container.querySelector('#btnCopyPbBroadcast');
        if (btnCopyBroadcast) {
            btnCopyBroadcast.addEventListener('click', () => {
                const bBlock = container.querySelector('#pbBroadcastCodeBlock');
                if (bBlock) {
                    navigator.clipboard.writeText(bBlock.innerText).then(() => {
                        const orig = btnCopyBroadcast.innerText;
                        btnCopyBroadcast.innerText = '✅ Copied!';
                        setTimeout(() => { btnCopyBroadcast.innerText = orig; }, 1800);
                    });
                }
            });
        }

        const btnCopilotPlaybook = container.querySelector('#btnAskCopilotPlaybook');
        if (btnCopilotPlaybook) {
            btnCopilotPlaybook.addEventListener('click', () => {
                const pb = PLAYBOOK_DATA[currentScenario];
                const p = getParams();
                if (window.PhishGuardCopilot && pb) {
                    window.PhishGuardCopilot.askWithContext(
                        `Act as the SOC Lead / Incident Commander for this ${pb.title} incident: Victim=${p.victimUser}, Attacker=${p.attackerSender}, MaliciousDomain=${p.maliciousDomain}. Provide a prioritized step-by-step executive triage checklist, containment PowerShell scripts, and communication protocol.`,
                        { scan: false, header: false, ioc: true, playbook: true }
                    );
                }
            });
        }
    }

    function updateProgress() {
        const container = document.getElementById('playbookContainer');
        const pb = PLAYBOOK_DATA[currentScenario];
        if (!container || !pb) return;
        let totalItems = 0;
        let completedItems = 0;
        pb.phases.forEach(phase => {
            phase.items.forEach(item => {
                totalItems++;
                if (checklistState[item.id]) completedItems++;
            });
        });
        const progressPct = totalItems > 0 ? Math.round((completedItems / totalItems) * 100) : 0;
        const progressText = container.querySelector('#pbProgressText');
        const progressBarFill = container.querySelector('#pbProgressBarFill');
        if (progressText) progressText.innerText = `${completedItems}/${totalItems} (${progressPct}%)`;
        if (progressBarFill) progressBarFill.style.width = `${progressPct}%`;
    }

    function updateScriptsAndBroadcast() {
        const container = document.getElementById('playbookContainer');
        const pb = PLAYBOOK_DATA[currentScenario];
        if (!container || !pb) return;
        const params = getParams();

        const scriptCodeBlock = container.querySelector('#pbScriptCodeBlock');
        const scriptTabTitle = container.querySelector('#pbScriptTabTitle');
        if (scriptCodeBlock && pb.scripts[currentScript]) {
            scriptCodeBlock.innerText = pb.scripts[currentScript](params);
            if (scriptTabTitle) {
                scriptTabTitle.innerText = `${currentScript.toUpperCase()} Remediation Snippet`;
            }
        }

        const broadcastCodeBlock = container.querySelector('#pbBroadcastCodeBlock');
        if (broadcastCodeBlock && pb.broadcast) {
            broadcastCodeBlock.innerText = pb.broadcast(params);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initPlaybooks);
    } else {
        initPlaybooks();
    }

    window.PhishGuardPlaybooks = {
        getCurrentState: () => ({
            scenario: currentScenario,
            title: PLAYBOOK_DATA[currentScenario]?.title,
            checklistState: checklistState[currentScenario],
            params: getParams()
        })
    };

})();


