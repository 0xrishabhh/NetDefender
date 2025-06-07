document.addEventListener('DOMContentLoaded', () => {
    const chatForm = document.getElementById('chat-form');
    const userInput = document.getElementById('user-input');
    const chatMessages = document.getElementById('chat-messages');
    const messagesContainer = chatMessages.querySelector('.space-y-4');

    // Focus input on page load
    userInput.focus();

    // Focus input when clicking anywhere in the terminal
    document.querySelector('.terminal-container').addEventListener('click', (e) => {
        if (!window.getSelection().toString()) {  // Don't focus if text is selected
            userInput.focus();
        }
    });

    // Prevent clicks on messages from removing focus
    messagesContainer.addEventListener('click', (e) => {
        e.stopPropagation();
    });

    function scrollToBottom() {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function typeWriter(element, text, speed = 30) {
        let i = 0;
        element.textContent = '';
        
        function type() {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
                setTimeout(type, speed);
                scrollToBottom();
            }
        }
        
        type();
    }

    function addMessage(content, isUser = false) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isUser ? 'user-message' : 'bot-message'}`;
        
        const promptSpan = document.createElement('span');
        promptSpan.className = 'prompt';
        promptSpan.textContent = isUser ? 'user@cyberchat:~$' : 'system@cyberchat:~$';
        
        const messageText = document.createElement('span');
        messageText.className = 'message-text';
        
        messageDiv.appendChild(promptSpan);
        messageDiv.appendChild(messageText);
        messagesContainer.appendChild(messageDiv);
        
        if (!isUser) {
            typeWriter(messageText, content);
        } else {
            messageText.textContent = content;
            scrollToBottom();
        }
    }

    function addTypingIndicator() {
        const indicator = document.createElement('div');
        indicator.className = 'typing-indicator';
        indicator.innerHTML = '<span></span><span></span><span></span>';
        messagesContainer.appendChild(indicator);
        scrollToBottom();
        return indicator;
    }

    function removeTypingIndicator(indicator) {
        if (indicator && indicator.parentNode) {
            indicator.parentNode.removeChild(indicator);
        }
    }

    // Add terminal startup effect
    setTimeout(() => {
        const startupMessages = [
            'Initializing secure connection...',
            'Establishing encrypted channel...',
            'Loading AI modules...',
            'System ready.'
        ];
        
        let delay = 0;
        startupMessages.forEach(msg => {
            setTimeout(() => {
                addMessage(msg, false);
            }, delay);
            delay += 1000;
        });
    }, 500);

    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const message = userInput.value.trim();
        if (!message) return;

        // Clear input and keep focus
        userInput.value = '';
        userInput.focus();

        // Add user message
        addMessage(message, true);

        // Add typing indicator
        const typingIndicator = addTypingIndicator();

        try {
            const response = await fetch('/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message }),
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            // Remove typing indicator
            removeTypingIndicator(typingIndicator);
            
            // Add bot response
            if (data.response) {
                addMessage(data.response);
            } else {
                throw new Error('Invalid response format');
            }
        } catch (error) {
            console.error('Error:', error);
            removeTypingIndicator(typingIndicator);
            addMessage('ERROR: ' + (error.message || 'Connection failed. Please try again.'));
        }
    });

    // Handle Ctrl+L to clear terminal
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'l') {
            e.preventDefault();
            messagesContainer.innerHTML = '';
            userInput.focus();
        }
    });

    // Prevent terminal click from removing focus when selecting text
    chatMessages.addEventListener('mousedown', (e) => {
        if (window.getSelection().toString()) {
            e.stopPropagation();
        }
    });

    // Add terminal cursor blink effect
    const cursor = document.createElement('span');
    cursor.className = 'cursor';
    cursor.textContent = '';
    userInput.parentNode.insertBefore(cursor, userInput.nextSibling);
    
    setInterval(() => {
        cursor.style.opacity = cursor.style.opacity === '0' ? '1' : '0';
    }, 530);

    // Handle scrolling
    chatMessages.addEventListener('scroll', () => {
        const isAtBottom = chatMessages.scrollHeight - chatMessages.scrollTop === chatMessages.clientHeight;
        chatMessages.classList.toggle('auto-scroll', isAtBottom);
    });
}); 