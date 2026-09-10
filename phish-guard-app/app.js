// 1. Grab the button and the text area from our HTML
const button = document.getElementById('scanButton');
const resultArea = document.getElementById('resultArea');
const inputArea = document.getElementById('emailInput');

// 2. Tell the button what to do when clicked
button.addEventListener('click', async function() {
    // Check if the user actually typed anything
    if (inputArea.value === "") {
        resultArea.textContent = "Please paste a message first!";
        return; // Stop running the code here
    }

    // Change the text to show it is working
    resultArea.textContent = "Analyzing message...";
    button.disabled = true; // prevent double-clicks while it's working

    try {
        const result = await analyzeMessage(inputArea.value);
        displayResult(result);
    } catch (error) {
        console.error(error);
        resultArea.textContent = "Something went wrong analyzing this message. Please try again.";
    } finally {
        button.disabled = false;
    }
});

// 3. This function sends the message to the AI and asks for a risk verdict
async function analyzeMessage(messageText) {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            model: "claude-sonnet-4-6",
            max_tokens: 1000,
            messages: [
                {
                    role: "user",
                    content: `You are a cybersecurity assistant analyzing a message for phishing signs.
Respond with ONLY a JSON object, no other text, no markdown code fences, in this exact format:
{"riskLevel": "Low" | "Medium" | "High", "explanation": "a 2-3 sentence plain-English explanation of why"}

Message to analyze:
"""
${messageText}
"""`
                }
            ],
        })
    });

    const data = await response.json();

    // Find the text block in the response
    const textBlock = data.content.find(block => block.type === "text");
    const rawText = textBlock.text.trim();

    // In case the model wraps it in ```json fences anyway, strip them out
    const cleanText = rawText.replace(/```json|```/g, "").trim();

    return JSON.parse(cleanText);
}

// 4. This function takes the AI's answer and shows it on the page
function displayResult(result) {
    resultArea.innerHTML = `
        <strong>Risk Level: ${result.riskLevel}</strong>
        <p>${result.explanation}</p>
    `;

    // Color-code the result