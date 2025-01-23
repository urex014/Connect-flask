function openChat(chatId) {
    document.getElementById('chat-name').innerText = `Chat ${chatId}`;
    const messagesDiv = document.getElementById('messages');
    fetch(`/get_messages?chat_id=${chatId}`)
        .then(response => response.json())
        .then(data => {
            messagesDiv.innerHTML = '';
            data.messages.forEach(msg => {
                const messageDiv = document.createElement('div');
                messageDiv.textContent = `${msg.sender}: ${msg.content}`;
                messagesDiv.appendChild(messageDiv);
            });
        });
}

document.querySelector('.send-btn').addEventListener('click', () => {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value.trim();
    if (message) {
        // Replace 1 with dynamic chat_id
        fetch('/send_message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: 1, message }),
        }).then(() => {
            messageInput.value = '';
            openChat(1); // Refresh messages
        });
    }
});
