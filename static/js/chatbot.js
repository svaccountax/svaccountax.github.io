
function toggleChat() {
  document.getElementById("chatbot-container")
    .classList.toggle("hidden");
}

async function sendMessage() {
  const input = document.getElementById("chat-input");
  const msg = input.value.trim();
  if (!msg) return;

  const chat = document.getElementById("chat-messages");

  chat.innerHTML += `<div class="user-msg">${msg}</div>`;
  input.value = "";
  chat.scrollTop = chat.scrollHeight;

  const typingId = "typing-" + Date.now();
  chat.innerHTML += `
    <div class="bot-msg typing" id="${typingId}">
      TaxAssist is typing…
    </div>
  `;
  chat.scrollTop = chat.scrollHeight;

  const res = await fetch("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: msg })
  });

  const data = await res.json();

  document.getElementById(typingId).remove();
  chat.innerHTML += `<div class="bot-msg">${data.reply}</div>`;

  if (data.suggestions) {
    chat.innerHTML += `
      <div class="quick-replies">
        ${data.suggestions.map(
          s => `<button onclick="quickSend('${s}')">${s}</button>`
        ).join("")}
      </div>
    `;
  }

  chat.scrollTop = chat.scrollHeight;
}

function quickSend(text) {
  document.getElementById("chat-input").value = text;
  sendMessage();
}
