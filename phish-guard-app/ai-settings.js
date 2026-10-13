/**
 * Phish-Guard - AI Settings Module (BYOK Pattern)
 * ------------------------------------------------
 * Manages provider, model selection, and API key storage in localStorage.
 * Storage key: 'pg_ai_settings'
 */

const AI_SETTINGS_KEY = 'pg_ai_settings';

const AI_PROVIDERS_CONFIG = {
    gemini: {
        name: 'Google Gemini',
        defaultModel: 'gemini-flash-latest',
        models: [
            { id: 'gemini-flash-latest', label: 'Gemini Flash (Auto-Updating Latest - Recommended)' },
            { id: 'gemini-3.1-flash-lite', label: 'Gemini 3.1 Flash-Lite (Fast & Cheap)' },
            { id: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash (Stable Fallback)' },
            { id: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro (Deep Reasoning)' },
            { id: 'gemini-3.1-pro-preview', label: 'Gemini 3.1 Pro Preview' }
        ],
        keyLabel: 'Google Gemini API Key',
        optLabel: '(Free Tier BYOK)',
        placeholder: 'Enter Gemini API key (AIzaSy...)',
        hintHtml: 'Free API key from <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener">Google AI Studio</a>.'
    },
    openai: {
        name: 'OpenAI (ChatGPT)',
        defaultModel: 'gpt-4o-mini',
        models: [
            { id: 'gpt-4o-mini', label: 'GPT-4o-mini (Fast & Cost-Efficient)' },
            { id: 'gpt-4o', label: 'GPT-4o (Omni High-Intelligence)' },
            { id: 'gpt-4-turbo', label: 'GPT-4 Turbo' },
            { id: 'o3-mini', label: 'o3-mini (Fast Reasoning)' },
            { id: 'o1-mini', label: 'o1-mini (Advanced Reasoning)' }
        ],
        keyLabel: 'OpenAI API Key',
        optLabel: '(BYOK)',
        placeholder: 'Enter OpenAI API key (sk-...)',
        hintHtml: 'Obtain key from <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener">OpenAI Developer Platform</a>.'
    },
    claude: {
        name: 'Anthropic Claude',
        defaultModel: 'claude-3-5-sonnet-latest',
        models: [
            { id: 'claude-3-5-sonnet-latest', label: 'Claude 3.5 Sonnet (Latest - State of the Art)' },
            { id: 'claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet (20241022)' },
            { id: 'claude-3-5-haiku-latest', label: 'Claude 3.5 Haiku (Fast & Intelligent)' },
            { id: 'claude-3-7-sonnet-latest', label: 'Claude 3.7 Sonnet (Hybrid Reasoning)' },
            { id: 'claude-3-opus-latest', label: 'Claude 3 Opus (Complex Analysis)' }
        ],
        keyLabel: 'Anthropic Claude API Key',
        optLabel: '(BYOK)',
        placeholder: 'Enter Claude API key (sk-ant-...)',
        hintHtml: 'Obtain key from <a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener">Anthropic Console</a>.'
    },
    heuristic: {
        name: 'Built-in Heuristic SOC Engine',
        defaultModel: 'offline-heuristic-soc',
        models: [
            { id: 'offline-heuristic-soc', label: 'Built-in Heuristic & Cognitive SOC (Zero-Key Offline)' }
        ],
        keyLabel: 'Zero-Key Offline Engine Active',
        optLabel: '(No key required)',
        placeholder: 'Offline mode active — no external API key needed',
        hintHtml: 'Fully offline cognitive + pattern analysis. No network calls for message analysis.'
    }
};

function saveAISettings({ provider, model, apiKey, vtKey }) {
    const current = getAISettings();
    const resolvedProvider = provider !== undefined ? provider : current.provider;
    const providerCfg = AI_PROVIDERS_CONFIG[resolvedProvider] || AI_PROVIDERS_CONFIG.gemini;

    const updated = {
        provider: resolvedProvider,
        model: model !== undefined ? model : (current.model || providerCfg.defaultModel),
        apiKey: apiKey !== undefined ? String(apiKey).trim() : current.apiKey,
        vtKey: vtKey !== undefined ? String(vtKey).trim() : (current.vtKey || '')
    };

    try {
        localStorage.setItem(AI_SETTINGS_KEY, JSON.stringify(updated));
    } catch (e) {
        console.warn('[Phish-Guard AI Settings] Failed to save settings to localStorage:', e);
    }
    if (window.PhishGuardCopilot && typeof window.PhishGuardCopilot.updateBadge === 'function') {
        window.PhishGuardCopilot.updateBadge();
    }
    return updated;
}

function getAISettings() {
    try {
        const raw = localStorage.getItem(AI_SETTINGS_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            const provider = parsed.provider && AI_PROVIDERS_CONFIG[parsed.provider] ? parsed.provider : 'gemini';
            const providerCfg = AI_PROVIDERS_CONFIG[provider];
            const validModel = (parsed.model && providerCfg.models.some(m => m.id === parsed.model))
                ? parsed.model
                : providerCfg.defaultModel;

            return {
                provider: provider,
                model: validModel,
                apiKey: typeof parsed.apiKey === 'string' ? parsed.apiKey : '',
                vtKey: typeof parsed.vtKey === 'string' ? parsed.vtKey : ''
            };
        }
    } catch (e) {
        console.warn('[Phish-Guard AI Settings] Failed to read settings from localStorage:', e);
    }
    return { provider: 'gemini', model: 'gemini-flash-latest', apiKey: '', vtKey: '' };
}


function updateModelOptions(modelSelect, provider, selectedModel) {
    if (!modelSelect) return;
    const cfg = AI_PROVIDERS_CONFIG[provider] || AI_PROVIDERS_CONFIG.gemini;
    modelSelect.innerHTML = '';

    cfg.models.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m.id;
        opt.textContent = m.label;
        if (m.id === selectedModel || (!selectedModel && m.id === cfg.defaultModel)) {
            opt.selected = true;
        }
        modelSelect.appendChild(opt);
    });
}

function initAISettingsUI() {
    const providerSelect = document.getElementById('ai-provider') || document.getElementById('aiProvider');
    const modelSelect = document.getElementById('ai-model') || document.getElementById('aiModel');
    const apiKeyInput = document.getElementById('ai-api-key') || document.getElementById('apiKeyInput');
    const apiKeyLabel = document.getElementById('apiKeyLabel');
    const apiKeyHint = document.getElementById('apiKeyHint');
    const vtKeyInput = document.getElementById('vtKey');
    const saveBtn = document.getElementById('save-settings');
    const testBtn = document.getElementById('test-connection');
    const statusEl = document.getElementById('connection-status');

    const currentSettings = getAISettings();

    if (providerSelect) providerSelect.value = currentSettings.provider;
    if (modelSelect) updateModelOptions(modelSelect, currentSettings.provider, currentSettings.model);
    if (apiKeyInput) {
        apiKeyInput.value = currentSettings.apiKey;
        apiKeyInput.disabled = (currentSettings.provider === 'heuristic');
    }
    if (vtKeyInput && currentSettings.vtKey) vtKeyInput.value = currentSettings.vtKey;

    function syncProviderMeta(provider) {
        const cfg = AI_PROVIDERS_CONFIG[provider] || AI_PROVIDERS_CONFIG.gemini;
        if (apiKeyLabel) apiKeyLabel.innerHTML = `${cfg.keyLabel} <span class="opt">${cfg.optLabel}</span>`;
        if (apiKeyHint) apiKeyHint.innerHTML = cfg.hintHtml;
        if (apiKeyInput) {
            apiKeyInput.placeholder = cfg.placeholder;
            apiKeyInput.disabled = (provider === 'heuristic');
        }
    }

    syncProviderMeta(currentSettings.provider);

    if (providerSelect && typeof providerSelect.addEventListener === 'function') {
        providerSelect.addEventListener('change', (e) => {
            const newProvider = e.target.value;
            const cfg = AI_PROVIDERS_CONFIG[newProvider] || AI_PROVIDERS_CONFIG.gemini;
            updateModelOptions(modelSelect, newProvider, cfg.defaultModel);
            syncProviderMeta(newProvider);

            saveAISettings({
                provider: newProvider,
                model: modelSelect ? modelSelect.value : cfg.defaultModel,
                apiKey: apiKeyInput ? apiKeyInput.value : '',
                vtKey: vtKeyInput ? vtKeyInput.value : ''
            });

            if (statusEl) {
                statusEl.textContent = '';
                statusEl.className = 'connection-status';
            }
        });
    }

    if (modelSelect && typeof modelSelect.addEventListener === 'function') {
        modelSelect.addEventListener('change', (e) => {
            saveAISettings({
                provider: providerSelect ? providerSelect.value : currentSettings.provider,
                model: e.target.value,
                apiKey: apiKeyInput ? apiKeyInput.value : '',
                vtKey: vtKeyInput ? vtKeyInput.value : ''
            });
        });
    }

    if (apiKeyInput && typeof apiKeyInput.addEventListener === 'function') {
        apiKeyInput.addEventListener('input', (e) => {
            saveAISettings({
                provider: providerSelect ? providerSelect.value : currentSettings.provider,
                model: modelSelect ? modelSelect.value : currentSettings.model,
                apiKey: e.target.value,
                vtKey: vtKeyInput ? vtKeyInput.value : ''
            });
        });
    }

    if (vtKeyInput && typeof vtKeyInput.addEventListener === 'function') {
        vtKeyInput.addEventListener('input', (e) => {
            saveAISettings({
                provider: providerSelect ? providerSelect.value : currentSettings.provider,
                model: modelSelect ? modelSelect.value : currentSettings.model,
                apiKey: apiKeyInput ? apiKeyInput.value : '',
                vtKey: e.target.value
            });
        });
    }

    if (saveBtn && typeof saveBtn.addEventListener === 'function') {
        saveBtn.addEventListener('click', () => {
            saveAISettings({
                provider: providerSelect ? providerSelect.value : currentSettings.provider,
                model: modelSelect ? modelSelect.value : currentSettings.model,
                apiKey: apiKeyInput ? apiKeyInput.value : '',
                vtKey: vtKeyInput ? vtKeyInput.value : ''
            });
            if (statusEl) {
                statusEl.textContent = '💾 Settings saved!';
                statusEl.className = 'connection-status success';
                setTimeout(() => {
                    if (statusEl.textContent.includes('saved')) {
                        statusEl.textContent = '';
                        statusEl.className = 'connection-status';
                    }
                }, 3000);
            }
        });
    }

    if (testBtn && typeof testBtn.addEventListener === 'function') {
        testBtn.addEventListener('click', async () => {
            if (!statusEl) return;
            statusEl.textContent = '⏳ Testing connection…';
            statusEl.className = 'connection-status testing';
            testBtn.disabled = true;

            try {
                const settings = getAISettings();
                if (settings.provider !== 'heuristic' && !settings.apiKey) {
                    throw new Error(`Please enter your ${AI_PROVIDERS_CONFIG[settings.provider]?.name || settings.provider} API key first.`);
                }
                if (typeof window.analyzeMessage === 'function') {
                    await window.analyzeMessage('Test message: Please verify your security alert settings.', settings);
                } else {
                    await new Promise(r => setTimeout(r, 500));
                }
                statusEl.textContent = `✅ Connected (${(AI_PROVIDERS_CONFIG[settings.provider]?.name || settings.provider)})`;
                statusEl.className = 'connection-status success';
            } catch (err) {
                statusEl.textContent = `❌ Failed: ${err.message || 'Connection error'}`;
                statusEl.className = 'connection-status error';
            } finally {
                testBtn.disabled = false;
            }
        });
    }
}

window.AI_SETTINGS_KEY = AI_SETTINGS_KEY;
window.AI_PROVIDERS_CONFIG = AI_PROVIDERS_CONFIG;
window.saveAISettings = saveAISettings;
window.getAISettings = getAISettings;
window.updateModelOptions = updateModelOptions;
window.initAISettingsUI = initAISettingsUI;

window.PhishGuardAISettings = {
    getSettings: getAISettings,
    saveSettings: saveAISettings,
    populateModelDropdown: function(provider, targetSelect) {
        const select = targetSelect || document.getElementById('ai-model') || document.getElementById('aiModel');
        if (select) {
            updateModelOptions(select, provider);
        }
    },
    updateModelOptions: updateModelOptions,
    AI_PROVIDERS_CONFIG: AI_PROVIDERS_CONFIG,
    AI_SETTINGS_KEY: AI_SETTINGS_KEY
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAISettingsUI);
} else {
    initAISettingsUI();
}

