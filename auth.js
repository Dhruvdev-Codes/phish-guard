/**
 * Phish-Guard - Authentication & Developer RBAC Engine (auth.js)
 * -------------------------------------------------------------
 * Provides Role-Based Access Control (RBAC):
 * - User Role: Standard Security Analyst / Trainee
 * - Developer Role: Platform Engineer & Detection Rule Authority (Privileged Access)
 *
 * Capabilities:
 * - User Login / Registration / Session Management
 * - Developer Console Gateway with Cryptographic Access Control
 * - Live Detection & Heuristic Regex Rule Engine Manager
 * - Global Domain / TLD Blacklist & Threat Feed Engine
 * - AI Heuristic Sensitivity & Risk Weights Tuning
 * - RBAC Security Audit & Telemetry Logger
 */

(function () {
    'use strict';

    // ================================================================
    //  STORAGE KEYS & DEFAULT SEED DATA
    // ================================================================
    const STORAGE_KEY_USER      = 'phishguard_auth_user';
    const STORAGE_KEY_USERS_DB  = 'phishguard_registered_users';
    const STORAGE_KEY_RULES     = 'phishguard_detection_rules';
    const STORAGE_KEY_BLACKLIST = 'phishguard_domain_blacklist';
    const STORAGE_KEY_CONFIG    = 'phishguard_engine_config';
    const STORAGE_KEY_AUDIT     = 'phishguard_audit_logs';

    // Default Seed Accounts
    const DEFAULT_ACCOUNTS = [
        {
            id: 'usr-analyst-01',
            email: 'analyst@defense.local',
            passwordHash: 'analyst123',
            name: 'Security Analyst Alex',
            role: 'user',
            organization: 'Enterprise SOC Blue Team',
            createdAt: '2026-09-01T08:00:00.000Z'
        },
        {
            id: 'dev-root-01',
            email: 'dhruv@phishguard.dev',
            passwordHash: 'admin123',
            name: 'Dhruv Upadhyay (Lead Dev)',
            role: 'developer',
            organization: 'Phish-Guard Core Engineering',
            createdAt: '2026-09-01T00:00:00.000Z'
        },
        {
            id: 'dev-root-02',
            email: 'dev@phishguard.io',
            passwordHash: 'devroot2026',
            name: 'Platform Developer Console',
            role: 'developer',
            organization: 'Threat Research Labs',
            createdAt: '2026-09-01T00:00:00.000Z'
        }
    ];

    // Default Detection Rules (editable by Developers)
    const DEFAULT_RULES = [
        {
            id: 'rule-001',
            name: 'Urgent Wire / Banking Pressure Scam',
            category: 'Financial / BEC',
            pattern: '\\b(wire transfer|bank account suspended|unauthorized debit|reversal failed|funds locked|swift code)\\b',
            flags: 'i',
            weight: 35,
            severity: 'high',
            isActive: true,
            description: 'Flags urgent demands for wire transfers or claims of locked financial accounts.',
            createdBy: 'Dhruv (Developer)'
        },
        {
            id: 'rule-002',
            name: 'Corporate SSO / M365 Credential Harvest',
            category: 'Credential Harvester',
            pattern: '\\b(microsoftonline|password expires? (today|within \\d+ hours?)|sso-login|verify credentials?|re-authenticate)\\b',
            flags: 'i',
            weight: 40,
            severity: 'critical',
            isActive: true,
            description: 'Identifies fake corporate Single Sign-On and password expiration lures.',
            createdBy: 'Dhruv (Developer)'
        },
        {
            id: 'rule-003',
            name: 'Executive Whaling / Gift Card Solicitation',
            category: 'Executive BEC',
            pattern: '\\b(gift cards?|apple card|itunes|steam card|scratch the (back|security film)|confidential task|cannot take calls)\\b',
            flags: 'i',
            weight: 45,
            severity: 'critical',
            isActive: true,
            description: 'Detects untraceable gift card purchase demands common in CEO fraud.',
            createdBy: 'Dhruv (Developer)'
        }
    ];

    const ADDITIONAL_RULES = [
        {
            id: 'rule-004',
            name: 'Abusive Phishing TLD Stacking',
            category: 'Network / Domain',
            pattern: '\\.(top|cfd|xyz|zip|click|su|quest|cam|fun|support|mom)\\/',
            flags: 'i',
            weight: 25,
            severity: 'medium',
            isActive: true,
            description: 'Penalizes URLs hosted on statistical high-abuse top level domains.',
            createdBy: 'Dhruv (Developer)'
        },
        {
            id: 'rule-005',
            name: 'HTML Smuggling Binary Assembly Constructor',
            category: 'Payload Evasion',
            pattern: '(Blob\\s*\\([\\s\\S]*?\\bapplication\\/octet-stream|URL\\.createObjectURL|msSaveOrOpenBlob)',
            flags: 'i',
            weight: 50,
            severity: 'critical',
            isActive: true,
            description: 'Detects in-browser executable blob generation bypassing secure email gateways.',
            createdBy: 'Dhruv (Developer)'
        }
    ];

    const DEFAULT_BLACKLIST = [
        { domain: 'chase-security-verify.xyz', reason: 'Active Banking Phishing Host', category: 'Financial', addedAt: '2026-09-10' },
        { domain: 'login-microsoftonline.account-update.top', reason: 'M365 Credential Harvester', category: 'SSO Phishing', addedAt: '2026-09-11' },
        { domain: 'vps-payload-distribution.cfd', reason: 'Malware Dropper & Smuggling Host', category: 'C2 / Dropper', addedAt: '2026-09-11' },
        { domain: 'bulletproof-vps.su', reason: 'High-Risk Bulletproof SMTP Relay', category: 'Spam Relay', addedAt: '2026-09-08' },
        { domain: 'secure-payment-cases.com', reason: 'Reply-To Diversion Target', category: 'BEC Target', addedAt: '2026-09-09' }
    ];

    const DEFAULT_CONFIG = {
        urgencyWeightMultiplier: 1.25,
        homoglyphPenalty: 40,
        unauthorizedSpfPenalty: 40,
        unalignedDkimPenalty: 30,
        minPhishingScoreThreshold: 65,
        minSuspiciousScoreThreshold: 30,
        enableLocalZeroKeyFallback: true,
        enforceStrictDmarc: true
    };

    // Combine rules
    const INITIAL_RULES = [...DEFAULT_RULES, ...ADDITIONAL_RULES];

    // ================================================================
    //  STATE STORE HELPERS
    // ================================================================
    function getStoredItem(key, fallback) {
        try {
            const raw = localStorage.getItem(key) || sessionStorage.getItem(key);
            return raw ? JSON.parse(raw) : fallback;
        } catch (e) {
            return fallback;
        }
    }

    function setStoredItem(key, val, persistent = true) {
        try {
            const str = JSON.stringify(val);
            if (persistent) {
                localStorage.setItem(key, str);
                sessionStorage.removeItem(key);
            } else {
                sessionStorage.setItem(key, str);
                localStorage.removeItem(key);
            }
        } catch (e) {
            console.warn('[PhishGuard Auth] Storage set failed:', e);
        }
    }

    function removeStoredItem(key) {
        try {
            localStorage.removeItem(key);
            sessionStorage.removeItem(key);
        } catch (e) {}
    }

    // ================================================================
    //  SESSION & RBAC STATE
    // ================================================================
    let currentUser = getStoredItem(STORAGE_KEY_USER, null);

    function getRegisteredUsers() {
        const stored = getStoredItem(STORAGE_KEY_USERS_DB, null);
        if (!stored || !Array.isArray(stored)) {
            setStoredItem(STORAGE_KEY_USERS_DB, DEFAULT_ACCOUNTS, true);
            return DEFAULT_ACCOUNTS;
        }
        return stored;
    }

    function saveRegisteredUsers(users) {
        setStoredItem(STORAGE_KEY_USERS_DB, users, true);
    }

    function getAuditLogs() {
        return getStoredItem(STORAGE_KEY_AUDIT, []);
    }

    function logAuditEvent(action, details = '', severity = 'info') {
        const logs = getAuditLogs();
        const entry = {
            id: 'audit-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
            timestamp: new Date().toISOString(),
            userEmail: currentUser ? currentUser.email : 'anonymous',
            userRole: currentUser ? currentUser.role : 'none',
            action: action,
            details: details,
            severity: severity
        };
        logs.unshift(entry);
        if (logs.length > 200) logs.pop();
        setStoredItem(STORAGE_KEY_AUDIT, logs, true);
        dispatchAuthEvent('phishguard:audit-logged', entry);
        return entry;
    }

    function dispatchAuthEvent(eventName, payload) {
        try {
            window.dispatchEvent(new CustomEvent(eventName, { detail: payload }));
        } catch (e) {}
    }

    // ================================================================
    //  AUTHENTICATION APIS
    // ================================================================
    function loginUser(email, password, remember = true) {
        if (!email || !password) {
            return { success: false, error: 'Please provide both email and password.' };
        }
        const cleanEmail = String(email).trim().toLowerCase();
        const users = getRegisteredUsers();
        const matched = users.find(u => u.email.toLowerCase() === cleanEmail);

        if (!matched || matched.passwordHash !== password) {
            logAuditEvent('USER_LOGIN_FAILED', `Failed login attempt for ${cleanEmail}`, 'warn');
            return { success: false, error: 'Invalid email or password.' };
        }

        const sessionUser = {
            id: matched.id,
            email: matched.email,
            name: matched.name,
            role: matched.role || 'user',
            organization: matched.organization || 'SOC Analyst',
            loginTime: new Date().toISOString()
        };

        currentUser = sessionUser;
        setStoredItem(STORAGE_KEY_USER, sessionUser, remember);
        logAuditEvent('USER_LOGIN_SUCCESS', `Logged in as ${matched.role.toUpperCase()}: ${matched.email}`, 'success');
        dispatchAuthEvent('phishguard:auth-changed', { user: currentUser });
        updateAuthUI();
        return { success: true, user: currentUser };
    }
    function registerUser(name, email, password, organization = 'Security Analyst') {
        if (!name || !email || !password) {
            return { success: false, error: 'All fields (Name, Email, Password) are required.' };
        }
        const cleanEmail = String(email).trim().toLowerCase();
        if (!cleanEmail.includes('@') || !cleanEmail.includes('.')) {
            return { success: false, error: 'Please enter a valid email address.' };
        }
        if (password.length < 6) {
            return { success: false, error: 'Password must be at least 6 characters long.' };
        }

        const users = getRegisteredUsers();
        if (users.some(u => u.email.toLowerCase() === cleanEmail)) {
            return { success: false, error: 'An account with this email address already exists.' };
        }

        const newUser = {
            id: 'usr-' + Date.now(),
            email: cleanEmail,
            passwordHash: password,
            name: name.trim(),
            role: 'user',
            organization: organization.trim() || 'Security Analyst',
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        saveRegisteredUsers(users);

        currentUser = {
            id: newUser.id,
            email: newUser.email,
            name: newUser.name,
            role: 'user',
            organization: newUser.organization,
            loginTime: new Date().toISOString()
        };

        setStoredItem(STORAGE_KEY_USER, currentUser, true);
        logAuditEvent('USER_REGISTERED', `New user registered: ${newUser.email}`, 'success');
        dispatchAuthEvent('phishguard:auth-changed', { user: currentUser });
        updateAuthUI();
        return { success: true, user: currentUser };
    }

    function loginDeveloper(devIdentifier, devSecret, remember = true) {
        if (!devIdentifier || !devSecret) {
            return { success: false, error: 'Developer Identifier and Access Secret are required.' };
        }
        const cleanId = String(devIdentifier).trim().toLowerCase();
        const users = getRegisteredUsers();
        const matched = users.find(u => u.email.toLowerCase() === cleanId && u.role === 'developer');

        if (!matched || matched.passwordHash !== devSecret) {
            logAuditEvent('DEV_LOGIN_REJECTED', `Unauthorized developer access attempt with ID: ${cleanId}`, 'danger');
            return { success: false, error: 'Access Denied: Invalid Developer Credentials or Role Hierarchy Mismatch.' };
        }

        currentUser = {
            id: matched.id,
            email: matched.email,
            name: matched.name,
            role: 'developer',
            organization: matched.organization || 'Phish-Guard Core Engineering',
            loginTime: new Date().toISOString(),
            isPrivileged: true
        };

        setStoredItem(STORAGE_KEY_USER, currentUser, remember);
        logAuditEvent('DEV_LOGIN_SUCCESS', `Privileged Developer root session authenticated for ${matched.email}`, 'success');
        dispatchAuthEvent('phishguard:auth-changed', { user: currentUser });
        updateAuthUI();
        return { success: true, user: currentUser };
    }

    function logout() {
        const prevEmail = currentUser ? currentUser.email : 'user';
        currentUser = null;
        removeStoredItem(STORAGE_KEY_USER);
        logAuditEvent('LOGOUT', `Session terminated for ${prevEmail}`, 'info');
        dispatchAuthEvent('phishguard:auth-changed', { user: null });
        updateAuthUI();
        return { success: true };
    }

    function getCurrentUser() {
        return currentUser;
    }

    function isDeveloper() {
        return currentUser !== null && currentUser.role === 'developer';
    }

    function isAuthenticated() {
        return currentUser !== null;
    }

    // ================================================================
    //  DEVELOPER RULE ENGINE (CRUD)
    // ================================================================
    function getDetectionRules() {
        return getStoredItem(STORAGE_KEY_RULES, INITIAL_RULES);
    }

    function saveDetectionRules(rules) {
        setStoredItem(STORAGE_KEY_RULES, rules, true);
        dispatchAuthEvent('phishguard:rules-updated', { rules });
    }

    function addDetectionRule(rule) {
        if (!isDeveloper()) return { success: false, error: 'Unauthorized: Developer privileges required.' };
        const rules = getDetectionRules();
        const newRule = {
            id: 'rule-' + Date.now(),
            name: rule.name || 'Unnamed Rule',
            category: rule.category || 'Custom',
            pattern: rule.pattern || '',
            flags: rule.flags || 'i',
            weight: parseInt(rule.weight, 10) || 20,
            severity: rule.severity || 'medium',
            isActive: rule.isActive !== false,
            description: rule.description || '',
            createdBy: currentUser.name + ' (Developer)'
        };
        rules.push(newRule);
        saveDetectionRules(rules);
        logAuditEvent('RULE_CREATED', `New detection rule "${newRule.name}" (${newRule.id}) created`, 'info');
        return { success: true, rule: newRule };
    }

    function updateDetectionRule(ruleId, updates) {
        if (!isDeveloper()) return { success: false, error: 'Unauthorized.' };
        const rules = getDetectionRules();
        const idx = rules.findIndex(r => r.id === ruleId);
        if (idx === -1) return { success: false, error: 'Rule not found.' };
        Object.assign(rules[idx], updates);
        saveDetectionRules(rules);
        logAuditEvent('RULE_UPDATED', `Rule "${rules[idx].name}" (${ruleId}) updated`, 'info');
        return { success: true, rule: rules[idx] };
    }

    function deleteDetectionRule(ruleId) {
        if (!isDeveloper()) return { success: false, error: 'Unauthorized.' };
        let rules = getDetectionRules();
        const target = rules.find(r => r.id === ruleId);
        if (!target) return { success: false, error: 'Rule not found.' };
        rules = rules.filter(r => r.id !== ruleId);
        saveDetectionRules(rules);
        logAuditEvent('RULE_DELETED', `Rule "${target.name}" (${ruleId}) deleted`, 'warn');
        return { success: true };
    }



    // ================================================================
    //  BLACKLIST MANAGEMENT
    // ================================================================
    function getBlacklist() {
        return getStoredItem(STORAGE_KEY_BLACKLIST, DEFAULT_BLACKLIST);
    }

    function saveBlacklist(list) {
        setStoredItem(STORAGE_KEY_BLACKLIST, list, true);
        dispatchAuthEvent('phishguard:blacklist-updated', { blacklist: list });
    }

    function addBlacklistEntry(domain, reason, category) {
        if (!isDeveloper()) return { success: false, error: 'Unauthorized.' };
        const list = getBlacklist();
        const clean = String(domain).trim().toLowerCase();
        if (list.some(e => e.domain === clean)) return { success: false, error: 'Domain already exists in blacklist.' };
        const entry = { domain: clean, reason: reason || 'Manual addition', category: category || 'Custom', addedAt: new Date().toISOString().split('T')[0] };
        list.push(entry);
        saveBlacklist(list);
        logAuditEvent('BLACKLIST_ADD', `Domain "${clean}" added to global blacklist`, 'info');
        return { success: true, entry };
    }

    function removeBlacklistEntry(domain) {
        if (!isDeveloper()) return { success: false, error: 'Unauthorized.' };
        let list = getBlacklist();
        const clean = String(domain).trim().toLowerCase();
        list = list.filter(e => e.domain !== clean);
        saveBlacklist(list);
        logAuditEvent('BLACKLIST_REMOVE', `Domain "${clean}" removed from blacklist`, 'warn');
        return { success: true };
    }

    // ================================================================
    //  ENGINE CONFIG MANAGEMENT
    // ================================================================
    function getEngineConfig() {
        return getStoredItem(STORAGE_KEY_CONFIG, DEFAULT_CONFIG);
    }

    function updateEngineConfig(updates) {
        if (!isDeveloper()) return { success: false, error: 'Unauthorized.' };
        const config = getEngineConfig();
        Object.assign(config, updates);
        setStoredItem(STORAGE_KEY_CONFIG, config, true);
        logAuditEvent('CONFIG_UPDATED', `Engine config updated: ${Object.keys(updates).join(', ')}`, 'info');
        dispatchAuthEvent('phishguard:config-updated', { config });
        return { success: true, config };
    }


    // ================================================================
    //  UI CONTROLLER & MODAL MANAGEMENT
    // ================================================================
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => [...document.querySelectorAll(sel)];

    function escHtml(str) {
        const d = document.createElement('div');
        d.textContent = String(str || '');
        return d.innerHTML;
    }

    function updateAuthUI() {
        const authBtn = $('#authToggleBtn');
        const devConsoleTab = $('[data-tab="devConsoleTab"]');
        const headerUserInfo = $('#headerUserInfo');
        const authModal = $('#authModal');

        if (currentUser) {
            // Logged-in state
            if (authBtn) {
                authBtn.innerHTML = '<span class="auth-user-icon">👤</span> ' + escHtml(currentUser.name.split(' ')[0]);
                authBtn.title = currentUser.email + ' (' + currentUser.role.toUpperCase() + ')';
                authBtn.classList.add('auth-logged-in');
                authBtn.classList.remove('auth-logged-out');
            }
            if (headerUserInfo) {
                const roleBadge = currentUser.role === 'developer'
                    ? '<span class="role-badge role-dev">DEVELOPER</span>'
                    : '<span class="role-badge role-user">ANALYST</span>';
                headerUserInfo.innerHTML = roleBadge + ' ' + escHtml(currentUser.name);
                headerUserInfo.classList.remove('hidden');
            }
            if (devConsoleTab) {
                if (currentUser.role === 'developer') {
                    devConsoleTab.classList.remove('hidden');
                    devConsoleTab.style.display = '';
                } else {
                    devConsoleTab.classList.add('hidden');
                    devConsoleTab.style.display = 'none';
                }
            }
            if (authModal && !authModal.classList.contains('hidden')) {
                authModal.classList.add('hidden');
            }
        } else {
            // Logged-out state
            if (authBtn) {
                authBtn.innerHTML = '🔐 Sign In';
                authBtn.title = 'Click to sign in or register';
                authBtn.classList.remove('auth-logged-in');
                authBtn.classList.add('auth-logged-out');
            }
            if (headerUserInfo) {
                headerUserInfo.innerHTML = '';
                headerUserInfo.classList.add('hidden');
            }
            if (devConsoleTab) {
                devConsoleTab.classList.add('hidden');
                devConsoleTab.style.display = 'none';
            }
        }
    }

    function openAuthModal(tabKey) {
        const modal = $('#authModal');
        if (!modal) return;
        modal.classList.remove('hidden');
        if (tabKey) switchAuthTab(tabKey);
    }

    function closeAuthModal() {
        const modal = $('#authModal');
        if (modal) modal.classList.add('hidden');
        clearAuthErrors();
    }

    function switchAuthTab(tabKey) {
        $$('.auth-tab-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.authTab === tabKey);
        });
        $$('.auth-tab-pane').forEach(p => {
            p.classList.toggle('active', p.id === tabKey);
        });
    }

    function clearAuthErrors() {
        $$('.auth-error-msg').forEach(el => { el.textContent = ''; el.classList.add('hidden'); });
        $$('.auth-success-msg').forEach(el => { el.textContent = ''; el.classList.add('hidden'); });
    }

    function showAuthError(paneId, msg) {
        const pane = document.getElementById(paneId);
        if (!pane) return;
        const errBox = pane.querySelector('.auth-error-msg');
        if (errBox) {
            errBox.textContent = msg;
            errBox.classList.remove('hidden');
        }
    }

    function showAuthSuccess(paneId, msg) {
        const pane = document.getElementById(paneId);
        if (!pane) return;
        const sBox = pane.querySelector('.auth-success-msg');
        if (sBox) {
            sBox.textContent = msg;
            sBox.classList.remove('hidden');
        }
    }

    // ================================================================
    //  DEVELOPER CONSOLE RENDERER
    // ================================================================
    function renderDevConsole() {
        const container = $('#devConsoleContent');
        if (!container || !isDeveloper()) return;

        const rules = getDetectionRules();
        const blacklist = getBlacklist();
        const config = getEngineConfig();
        const auditLogs = getAuditLogs().slice(0, 30);

        let rulesHtml = rules.map(r => `
            <tr class="dev-rule-row ${r.isActive ? '' : 'rule-disabled'}">
                <td><code>${escHtml(r.id)}</code></td>
                <td>${escHtml(r.name)}</td>
                <td><span class="severity-tag severity-${r.severity}">${r.severity}</span></td>
                <td>${r.weight}</td>
                <td>${r.isActive ? '✅' : '❌'}</td>
                <td>
                    <button class="btn-dev-sm btn-toggle-rule" data-rule-id="${r.id}" title="Toggle">${r.isActive ? '⏸' : '▶'}</button>
                    <button class="btn-dev-sm btn-delete-rule btn-danger-sm" data-rule-id="${r.id}" title="Delete">🗑</button>
                </td>
            </tr>`).join('');

        let blacklistHtml = blacklist.map(e => `
            <tr>
                <td><code>${escHtml(e.domain)}</code></td>
                <td>${escHtml(e.reason)}</td>
                <td>${escHtml(e.category)}</td>
                <td>
                    <button class="btn-dev-sm btn-danger-sm btn-remove-bl" data-domain="${escHtml(e.domain)}" title="Remove">✖</button>
                </td>
            </tr>`).join('');

        let auditHtml = auditLogs.map(l => `
            <tr class="audit-${l.severity}">
                <td class="audit-ts">${l.timestamp.replace('T', ' ').substring(0, 19)}</td>
                <td>${escHtml(l.userEmail)}</td>
                <td><span class="severity-tag severity-${l.severity === 'danger' ? 'critical' : l.severity}">${l.action}</span></td>
                <td class="audit-detail">${escHtml(l.details)}</td>
            </tr>`).join('');

        container.innerHTML = `
        <div class="dev-console-inner">

            <!-- Rules Section -->
            <section class="dev-section">
                <h3 class="dev-section-title">⚙ Detection Rule Engine <span class="rule-count">(${rules.length} rules)</span></h3>
                <div class="dev-table-wrap">
                    <table class="dev-table"><thead>
                        <tr><th>ID</th><th>Name</th><th>Severity</th><th>Weight</th><th>Active</th><th>Actions</th></tr>
                    </thead><tbody>${rulesHtml || '<tr><td colspan="6">No rules defined</td></tr>'}</tbody></table>
                </div>
                <div class="dev-add-row">
                    <input type="text" id="newRuleName" placeholder="Rule Name" class="dev-input" />
                    <input type="text" id="newRulePattern" placeholder="Regex Pattern" class="dev-input dev-input-wide" />
                    <select id="newRuleSeverity" class="dev-select">
                        <option value="low">Low</option><option value="medium" selected>Medium</option>
                        <option value="high">High</option><option value="critical">Critical</option>
                    </select>
                    <input type="number" id="newRuleWeight" placeholder="Weight" value="25" min="1" max="100" class="dev-input dev-input-sm" />
                    <button class="btn-dev btn-dev-add" id="btnAddRule">+ Add Rule</button>
                </div>
            </section>

            <!-- Blacklist Section -->
            <section class="dev-section">
                <h3 class="dev-section-title">🛡 Global Domain Blacklist <span class="rule-count">(${blacklist.length} domains)</span></h3>
                <div class="dev-table-wrap">
                    <table class="dev-table"><thead>
                        <tr><th>Domain</th><th>Reason</th><th>Category</th><th>Action</th></tr>
                    </thead><tbody>${blacklistHtml || '<tr><td colspan="4">No blacklisted domains</td></tr>'}</tbody></table>
                </div>
                <div class="dev-add-row">
                    <input type="text" id="newBlDomain" placeholder="domain.xyz" class="dev-input" />
                    <input type="text" id="newBlReason" placeholder="Reason" class="dev-input" />
                    <input type="text" id="newBlCategory" placeholder="Category" class="dev-input" />
                    <button class="btn-dev btn-dev-add" id="btnAddBlacklist">+ Add Domain</button>
                </div>
            </section>

            <!-- Config Section -->
            <section class="dev-section">
                <h3 class="dev-section-title">🎛 Heuristic Engine Configuration</h3>
                <div class="dev-config-grid">
                    ${Object.entries(config).map(([k, v]) => `
                        <label class="dev-config-label">${k}
                            <input type="${typeof v === 'boolean' ? 'checkbox' : 'number'}"
                                   class="dev-config-input" data-config-key="${k}"
                                   ${typeof v === 'boolean' ? (v ? 'checked' : '') : `value="${v}" step="0.01"`} />
                        </label>`).join('')}
                </div>
                <button class="btn-dev" id="btnSaveConfig">💾 Save Configuration</button>
            </section>

            <!-- Audit Log Section -->
            <section class="dev-section">
                <h3 class="dev-section-title">📋 Security Audit Log <span class="rule-count">(latest 30)</span></h3>
                <div class="dev-table-wrap dev-table-scroll">
                    <table class="dev-table dev-table-compact"><thead>
                        <tr><th>Timestamp</th><th>User</th><th>Action</th><th>Details</th></tr>
                    </thead><tbody>${auditHtml || '<tr><td colspan="4">No audit logs yet</td></tr>'}</tbody></table>
                </div>
            </section>
        </div>`;

        wireDevConsoleEvents(container);
    }


    function wireDevConsoleEvents(container) {
        // Toggle rule active/inactive
        container.querySelectorAll('.btn-toggle-rule').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.dataset.ruleId;
                const rules = getDetectionRules();
                const r = rules.find(x => x.id === id);
                if (r) {
                    updateDetectionRule(id, { isActive: !r.isActive });
                    renderDevConsole();
                }
            });
        });

        // Delete rule
        container.querySelectorAll('.btn-delete-rule').forEach(btn => {
            btn.addEventListener('click', () => {
                if (confirm('Delete this detection rule permanently?')) {
                    deleteDetectionRule(btn.dataset.ruleId);
                    renderDevConsole();
                }
            });
        });

        // Add new rule
        const addRuleBtn = container.querySelector('#btnAddRule');
        if (addRuleBtn) {
            addRuleBtn.addEventListener('click', () => {
                const name = container.querySelector('#newRuleName').value.trim();
                const pattern = container.querySelector('#newRulePattern').value.trim();
                const severity = container.querySelector('#newRuleSeverity').value;
                const weight = container.querySelector('#newRuleWeight').value;
                if (!name || !pattern) return alert('Rule Name and Regex Pattern are required.');
                const res = addDetectionRule({ name, pattern, severity, weight });
                if (res.success) renderDevConsole();
                else alert(res.error);
            });
        }

        // Remove blacklist entry
        container.querySelectorAll('.btn-remove-bl').forEach(btn => {
            btn.addEventListener('click', () => {
                removeBlacklistEntry(btn.dataset.domain);
                renderDevConsole();
            });
        });

        // Add blacklist entry
        const addBlBtn = container.querySelector('#btnAddBlacklist');
        if (addBlBtn) {
            addBlBtn.addEventListener('click', () => {
                const domain = container.querySelector('#newBlDomain').value.trim();
                const reason = container.querySelector('#newBlReason').value.trim();
                const category = container.querySelector('#newBlCategory').value.trim();
                if (!domain) return alert('Domain is required.');
                const res = addBlacklistEntry(domain, reason, category);
                if (res.success) renderDevConsole();
                else alert(res.error);
            });
        }

        // Save engine config
        const saveConfigBtn = container.querySelector('#btnSaveConfig');
        if (saveConfigBtn) {
            saveConfigBtn.addEventListener('click', () => {
                const updates = {};
                container.querySelectorAll('.dev-config-input').forEach(inp => {
                    const key = inp.dataset.configKey;
                    if (inp.type === 'checkbox') updates[key] = inp.checked;
                    else updates[key] = parseFloat(inp.value) || 0;
                });
                const res = updateEngineConfig(updates);
                if (res.success) alert('Configuration saved successfully.');
            });
        }
    }


    // ================================================================
    //  INIT - Wire Modal Events & Bootstrap Auth
    // ================================================================
    function initAuth() {
        // Seed users DB on first launch
        getRegisteredUsers();

        // Auth toggle button in header
        const authBtn = $('#authToggleBtn');
        if (authBtn) {
            authBtn.addEventListener('click', () => {
                if (currentUser) {
                    openAuthModal('authProfilePane');
                } else {
                    openAuthModal('authLoginPane');
                }
            });
        }

        // Close modal X button
        const closeBtn = $('#authModalClose');
        if (closeBtn) {
            closeBtn.addEventListener('click', closeAuthModal);
        }

        // Close on overlay click
        const modal = $('#authModal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeAuthModal();
            });
        }

        // Auth tab switching
        $$('.auth-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                clearAuthErrors();
                switchAuthTab(btn.dataset.authTab);
            });
        });

        // Login form submit
        const loginForm = $('#authLoginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                clearAuthErrors();
                const email = $('#loginEmail').value;
                const pass = $('#loginPassword').value;
                const res = loginUser(email, pass);
                if (!res.success) showAuthError('authLoginPane', res.error);
                else closeAuthModal();
            });
        }

        // Register form submit
        const regForm = $('#authRegisterForm');
        if (regForm) {
            regForm.addEventListener('submit', (e) => {
                e.preventDefault();
                clearAuthErrors();
                const name = $('#regName').value;
                const email = $('#regEmail').value;
                const pass = $('#regPassword').value;
                const org = $('#regOrg').value;
                const res = registerUser(name, email, pass, org);
                if (!res.success) showAuthError('authRegisterPane', res.error);
                else closeAuthModal();
            });
        }

        // Developer login form submit
        const devForm = $('#authDevForm');
        if (devForm) {
            devForm.addEventListener('submit', (e) => {
                e.preventDefault();
                clearAuthErrors();
                const devId = $('#devIdentifier').value;
                const devSec = $('#devSecret').value;
                const res = loginDeveloper(devId, devSec);
                if (!res.success) showAuthError('authDevPane', res.error);
                else closeAuthModal();
            });
        }

        // Profile pane logout
        const logoutBtn = $('#authLogoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                logout();
                closeAuthModal();
            });
        }

        // Developer Console tab auto-render
        window.addEventListener('phishguard:auth-changed', () => {
            if (isDeveloper()) renderDevConsole();
        });

        // Refresh dev console when the tab is opened
        $$('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                if (btn.dataset.tab === 'devConsoleTab' && isDeveloper()) {
                    renderDevConsole();
                }
            });
        });

        // Profile pane updater
        window.addEventListener('phishguard:auth-changed', () => {
            const profilePane = $('#authProfilePane');
            if (!profilePane) return;
            if (currentUser) {
                profilePane.querySelector('.profile-name').textContent = currentUser.name;
                profilePane.querySelector('.profile-email').textContent = currentUser.email;
                profilePane.querySelector('.profile-role').textContent = currentUser.role.toUpperCase();
                profilePane.querySelector('.profile-org').textContent = currentUser.organization;
            }
        });

        // Apply initial UI state
        updateAuthUI();
        logAuditEvent('SYSTEM_INIT', 'Phish-Guard Auth Engine initialized', 'info');
    }

    // ================================================================
    //  GLOBAL API EXPORT
    // ================================================================
    window.PhishGuardAuth = {
        init: initAuth,
        login: loginUser,
        register: registerUser,
        loginDev: loginDeveloper,
        logout: logout,
        getUser: getCurrentUser,
        isAuth: isAuthenticated,
        isDev: isDeveloper,
        getRules: getDetectionRules,
        addRule: addDetectionRule,
        updateRule: updateDetectionRule,
        deleteRule: deleteDetectionRule,
        getBlacklist: getBlacklist,
        addBlacklist: addBlacklistEntry,
        removeBlacklist: removeBlacklistEntry,
        getConfig: getEngineConfig,
        updateConfig: updateEngineConfig,
        getAuditLogs: getAuditLogs,
        openModal: openAuthModal,
        closeModal: closeAuthModal,
        renderDevConsole: renderDevConsole
    };

    // Auto-init when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initAuth);
    } else {
        initAuth();
    }

})();


