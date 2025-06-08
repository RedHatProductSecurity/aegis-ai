// TODO: I really do not know js ... prob needs to be refactored.

const chatContainer = document.getElementById('chat-container');
const promptInput = document.getElementById('prompt-input');
const sendButton = document.getElementById('send-button');

let isSending = false;
let chatHistory = []; // Array to store messages for context, format: [{role, timestamp, content}]

function appendMessage(message) {
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message', message.role);

    const bubbleDiv = document.createElement('div');
    bubbleDiv.classList.add('message-bubble');
    bubbleDiv.textContent = message.content;

    messageDiv.appendChild(bubbleDiv);
    chatContainer.appendChild(messageDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

async function sendMessage() {
    if (isSending) return;
    const prompt = promptInput.value.trim();
    if (!prompt) return;

    isSending = true;
    sendButton.disabled = true;
    promptInput.value = '';

    // Append user message to display and local history
    const userMessage = {
        role: 'user',
        timestamp: new Date().toISOString(),
        content: prompt,
    };
    appendMessage(userMessage);
    chatHistory.push(userMessage); // Add to local history for context

    try {
        const formData = new FormData();
        formData.append('prompt', prompt);
        formData.append('history_json', JSON.stringify(chatHistory));

        const response = await fetch('/chat/', {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const reader = response.body?.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';
        let lastModelMessageBubble = null; // Reference to the content bubble for AI
        let aiFullResponseContent = ""; // To store AI's full response for chatHistory
        let previousContent = ""; // To track content from previous chunk

        while (true && reader) {
            const { done, value } = await reader.read();
            buffer += decoder.decode(value, { stream: true });

            let newlineIndex;
            while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
                const messageJson = buffer.substring(0, newlineIndex).trim();
                buffer = buffer.substring(newlineIndex + 1);

                if (messageJson) {
                    const message = JSON.parse(messageJson);
                    if (message.role === 'model') {
                        if (!lastModelMessageBubble) {
                            const messageDiv = document.createElement('div');
                            messageDiv.classList.add('message', 'model');
                            lastModelMessageBubble = document.createElement('div');
                            lastModelMessageBubble.classList.add('message-bubble');
                            messageDiv.appendChild(lastModelMessageBubble);
                            chatContainer.appendChild(messageDiv);
                            chatContainer.scrollTop = chatContainer.scrollHeight;
                        }

                        const currentContent = message.content;
                        const delta = currentContent.substring(previousContent.length);
                        lastModelMessageBubble.textContent += delta;
                        previousContent = currentContent;

                        aiFullResponseContent += delta;
                    } else if (message.role === 'user') {
                        // This handles the user's echoed prompt from the server.
                        // We've already appended it locally, so DO NOT re-append to avoid duplication.
                    } else {
                         console.warn("Received unexpected message type from stream:", message);
                         appendMessage(message); // If it's a new, unknown message type, append it
                    }
                    // Keep scrolling to bottom
                    if (message.role === 'model' || (message.role !== 'user' && lastModelMessageBubble)) { // Only scroll if appending to AI or new unknown message
                        chatContainer.scrollTop = chatContainer.scrollHeight;
                    }
                }
            }
            if (done) break;
        }

        // After streaming is complete, add the AI's full response to local history
        const aiMessage = {
            role: 'model',
            timestamp: new Date().toISOString(),
            content: aiFullResponseContent,
        };
        chatHistory.push(aiMessage);

    } catch (error) {
        console.error('Error sending message:', error);
        appendMessage({
            role: 'model',
            timestamp: new Date().toISOString(),
            content: `Error: Could not get response. ${error}`,
        });
        if (chatHistory.length > 0 && chatHistory[chatHistory.length - 1].role === 'user') {
            chatHistory.pop();
        }
    } finally {
        isSending = false;
        sendButton.disabled = false;
        lastModelMessageBubble = null;
        previousContent = "";
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }
}

sendButton.addEventListener('click', sendMessage);
promptInput.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        sendMessage();
    }
});

