/**
 * Phish-Guard - AI Providers Module (BYOK Pattern)
 * ------------------------------------------------
 * Direct client-side integrations with Google Gemini, OpenAI, and Anthropic Claude.
 * Standard signature: (promptText, { apiKey, model }) => Promise<string>
 */

async function analyzeWithGemini(promptText, { apiKey, model }) {
    if (!apiKey) throw new Error('Google Gemini API Key is missing. Please enter your key in Settings.');
    const targetModel = model || 'gemini-flash-latest';

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(targetModel)}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{ parts: [{ text: promptText }] }],
            generationConfig: {
                temperature: 0.2,
                maxOutputTokens: 2048
            }
        })
    });

    if (!res.ok) {
        let errMessage = '';
        try {
            const errData = await res.json();
            errMessage = (errData.error && errData.error.message) || res.statusText;
        } catch (_) {
            errMessage = await res.text();
        }
        if (res.status === 400 && String(errMessage).includes('API key')) {
            throw new Error(`Invalid Gemini API Key: ${errMessage}`);
        }
        if (res.status === 404) {
            throw new Error(`Gemini model "${targetModel}" not found (HTTP 404): ${errMessage}`);
        }
        if (res.status === 429) {
            throw new Error(`Gemini API rate limit or quota reached (HTTP 429): ${errMessage}`);
        }
        throw new Error(`Gemini API HTTP ${res.status}: ${errMessage}`);
    }

    const data = await res.json();
    const candidate = data.candidates && data.candidates[0];
    const textPart = candidate && candidate.content && candidate.content.parts && candidate.content.parts[0];

    if (!textPart || !textPart.text) {
        throw new Error('Gemini API returned an empty response.');
    }

    return textPart.text;
}

async function analyzeWithOpenAI(promptText, { apiKey, model }) {
    if (!apiKey) throw new Error('OpenAI API Key is missing. Please enter your key in Settings.');
    const targetModel = model || 'gpt-4o-mini';

    const res = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
            model: targetModel,
            messages: [{ role: 'user', content: promptText }],
            temperature: 0.2
        })
    });

    if (!res.ok) {
        let errMessage = '';
        try {
            const errData = await res.json();
            errMessage = (errData.error && errData.error.message) || res.statusText;
        } catch (_) {
            errMessage = await res.text();
        }
        if (res.status === 401) {
            throw new Error(`OpenAI API Key is invalid or expired (HTTP 401): ${errMessage}`);
        }
        if (res.status === 429) {
            throw new Error(`OpenAI rate limit reached or insufficient credits (HTTP 429): ${errMessage}`);
        }
        if (res.status === 404) {
            throw new Error(`OpenAI model "${targetModel}" not found (HTTP 404): ${errMessage}`);
        }
        throw new Error(`OpenAI API HTTP ${res.status}: ${errMessage}`);
    }

    const data = await res.json();
    const content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;

    if (!content) {
        throw new Error('OpenAI returned an empty response.');
    }

    return content;
}

async function analyzeWithClaude(promptText, { apiKey, model }) {
    if (!apiKey) throw new Error('Anthropic Claude API Key is missing. Please enter your key in Settings.');
    const targetModel = model || 'claude-3-5-sonnet-latest';

    const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
            model: targetModel,
            max_tokens: 1500,
            messages: [{ role: 'user', content: promptText }]
        })
    });

    if (!res.ok) {
        let errMessage = '';
        try {
            const errData = await res.json();
            errMessage = (errData.error && errData.error.message) || res.statusText;
        } catch (_) {
            errMessage = await res.text();
        }
        if (res.status === 401) {
            throw new Error(`Claude API Key is invalid or unauthorized (HTTP 401): ${errMessage}`);
        }
        if (res.status === 429) {
            throw new Error(`Anthropic Claude rate limit reached (HTTP 429): ${errMessage}`);
        }
        if (res.status === 404) {
            throw new Error(`Claude model "${targetModel}" not found (HTTP 404): ${errMessage}`);
        }
        throw new Error(`Claude API HTTP ${res.status}: ${errMessage}`);
    }

    const data = await res.json();
    if (data.content && Array.isArray(data.content) && data.content.length > 0) {
        const textBlocks = data.content.filter(b => b.type === 'text' || b.text).map(b => b.text || '');
        if (textBlocks.length > 0) return textBlocks.join('\n');
    }

    throw new Error('Claude returned an empty or unrecognized response format.');
}

window.analyzeWithGemini = analyzeWithGemini;
window.analyzeWithOpenAI = analyzeWithOpenAI;
window.analyzeWithClaude = analyzeWithClaude;
