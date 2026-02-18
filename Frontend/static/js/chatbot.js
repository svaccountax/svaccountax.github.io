 let chatbotInitialized = false;
const WHATSAPP_NUMBER = "919676359019";
 
function toggleChat() {
  const chat = document.getElementById("chatbot-container");
  chat.classList.toggle("hidden");
 
  if (!chatbotInitialized && !chat.classList.contains("hidden")) {
    initChatbot();
    chatbotInitialized = true;
  }
}
 
/* ------------------ UI HELPERS ------------------ */
 
function addBotMessage(text) {
  const chat = document.getElementById("chat-messages");
  const div = document.createElement("div");
  div.className = "bot-msg";
  div.innerText = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}
 
function addUserMessage(text) {
  const chat = document.getElementById("chat-messages");
  const div = document.createElement("div");
  div.className = "user-msg";
  div.innerText = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}
 
/* ------------------ SUGGESTIONS ------------------ */
 
function renderSuggestions(suggestions) {
  const container = document.getElementById("suggestions");
  container.innerHTML = "";
 
  if (!suggestions) return;
 
  suggestions.forEach(text => {
    if (text.toLowerCase().includes("expert")) {
      const a = document.createElement("a");
      a.href = `https://wa.me/${WHATSAPP_NUMBER}?text=Hi%20I%20need%20tax%20assistance`;
      a.target = "_blank";
      a.className = "quick-btn";
      a.innerText = "Chat on WhatsApp";
      container.appendChild(a);
    } else {
      const btn = document.createElement("button");
      btn.className = "quick-btn";
      btn.innerText = text;
      btn.onclick = () => sendToBot(text.toLowerCase());
      container.appendChild(btn);
    }
  });
}
 
/* ------------------ BOT COMMUNICATION ------------------ */
 
function sendToBot(message) {
  fetch("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message })
  })
    .then(res => res.json())
    .then(data => {
      addBotMessage(data.reply);
      renderSuggestions(data.suggestions);
    });
}
 
function sendMessage() {
  const input = document.getElementById("chat-input");
  const message = input.value.trim();
  if (!message) return;
 
  addUserMessage(message);
  input.value = "";
  sendToBot(message.toLowerCase());
}
 
/* ------------------ INIT ------------------ */
 
function initChatbot() {
  addBotMessage(
    "Hi 👋 Welcome to SV Accountax Crew.\n\n" +
    "I can help with basic information about our services.\n\n" +
    "For personalised advice, our expert is available on WhatsApp."
  );
 
  renderSuggestions(["Services", "Plans", "Talk to Expert"]);
}