/**
 * Phish-Guard - AI Threat Analyzer & Prompt Dispatcher
 * ---------------------------------------------------
 * Builds structured cybersecurity analysis prompts and dispatches requests
 * to the configured AI provider (Gemini, OpenAI, Claude, or Heuristic fallback).
 */

/**
 * Builds the standardized phishing detection prompt
 * @param {string} messageText
 * @returns {string}
 */
function buildPhishingPrompt(messageText) {
    return `You are a cybersecurity assistant specialized in phishing detection.
Analyze the following message for phishing indicators: urgency/pressure language,
mismatched or spoofed sender/links, requests for credentials or payment,
generic greetings, spelling/grammar red flags, and suspicious attachments.

Return your analysis as:
1. Risk Level: Low / Medium / High
2. Key Indicators Found: (bulleted list)
3. Recommendation: (one short sentence)

Message to analyze:
"""
${messageText}
"""`;
}

/**
 * Dispatches message text to the selected AI provider
 * @param {string} messageText
 * @param {Object} [customSettings]
 * @returns {Promise<string>}
 */
async function analyzeMessage(messageText, customSettings = null) {
    const settings = customSettings || (typeof getAISettings === 'function'
        ? getAISettings()
        : { provider: 'gemini', model: 'gemini-flash-latest', apiKey: '' });

    if (!messageText || !String(messageText).trim()) {
        throw new Error('Please enter message text to analyze.');
    }

    const prompt = buildPhishingPrompt(messageText);

    switch (settings.provider) {
        case 'gemini':
            if (!settings.apiKey) throw new Error('Google Gemini API key is required. Please set it in AI Settings.');
            return analyzeWithGemini(prompt, settings);

        case 'openai':
            if (!settings.apiKey) throw new Error('OpenAI API key is required. Please set it in AI Settings.');
            return analyzeWithOpenAI(prompt, settings);

        case 'claude':
            if (!settings.apiKey) throw new Error('Anthropic Claude API key is required. Please set it in AI Settings.');
            return analyzeWithClaude(prompt, settings);

        case 'heuristic':
            if (typeof analyzeHeuristics === 'function') {
                const urls = typeof extractURLs === 'function' ? extractURLs(messageText) : [];
                const h = analyzeHeuristics(messageText, urls);
                const lvl = h.verdict === 'PHISHING' ? 'High' : h.verdict === 'SUSPICIOUS' ? 'Medium' : 'Low';
                const techs = (h.techniques && h.techniques.length)
                    ? h.techniques.map(t => '• ' + t).join('\n')
                    : '• No critical social engineering indicators detected.';
                const rec = (h.recommendations && h.recommendations[0]) || 'Exercise normal caution before clicking links or sharing info.';
                return `1. Risk Level: ${lvl}\n2. Key Indicators Found:\n${techs}\n3. Recommendation: ${rec}`;
            }
            return `1. Risk Level: Low\n2. Key Indicators Found:\n• Message parsed via local heuristic analyzer\n3. Recommendation: Verify sender details if unexpected.`;

        default:
            throw new Error(`Unsupported AI provider selected: ${settings.provider}`);
    }
}

/**
 * Parses 3-part AI plain text response into structured data
 * @param {string} rawText
 * @returns {Object}
 */
function parsePhishingAnalysis(rawText) {
    if (!rawText || typeof rawText !== 'string') {
        return {
            riskLevel: 'Unknown',
            riskScore: 50,
            verdict: 'SUSPICIOUS',
            keyIndicators: [],
            recommendation: 'Verify sender credentials.',
            raw: ''
        };
    }

    const riskMatch = rawText.match(/1\.\s*Risk\s*Level:\s*([^\n\r]+)/i);
    const recMatch = rawText.match(/3\.\s*Recommendation:\s*([^\n\r]+)/i);

    let riskLevel = 'Medium';
    let riskScore = 55;
    let verdict = 'SUSPICIOUS';

    if (riskMatch) {
        const parsed = riskMatch[1].trim();
        if (/high/i.test(parsed)) {
            riskLevel = 'High';
            riskScore = 88;
            verdict = 'PHISHING';
        } else if (/low/i.test(parsed)) {
            riskLevel = 'Low';
            riskScore = 15;
            verdict = 'SAFE';
        } else {
            riskLevel = 'Medium';
            riskScore = 55;
            verdict = 'SUSPICIOUS';
        }
    }

    const recommendation = recMatch ? recMatch[1].trim() : 'Exercise caution and verify the sender before opening links or attachments.';

    const indicators = [];
    const lines = rawText.split('\n');
    let inIndicators = false;

    for (let line of lines) {
        const trimmed = line.trim();
        if (/2\.\s*Key\s*Indicators/i.test(trimmed)) {
            inIndicators = true;
            continue;
        }
        if (/3\.\s*Recommendation/i.test(trimmed)) {
            inIndicators = false;
            break;
        }
        if (inIndicators && (trimmed.startsWith('•') || trimmed.startsWith('-') || trimmed.startsWith('*') || /^\d+\./.test(trimmed))) {
            const clean = trimmed.replace(/^[•\-*\d.]+\s*/, '').trim();
            if (clean) indicators.push(clean);
        }
    }

    return {
        riskLevel,
        riskScore,
        verdict,
        keyIndicators: indicators,
        recommendation,
        raw: rawText
    };
}

// Global exposure
window.buildPhishingPrompt = buildPhishingPrompt;
window.analyzeMessage = analyzeMessage;
window.parsePhishingAnalysis = parsePhishingAnalysis;
