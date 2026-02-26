let chatbotInitialized = false;
let botBusy = false;

const WHATSAPP_NUMBER = "919676359019";
const CHAT_HISTORY_KEY = "sv_chat_history_v1";
const CHAT_LANG_KEY = "sv_chat_lang_v1";

let currentChatLang = "en";
try {
  const savedLang = sessionStorage.getItem(CHAT_LANG_KEY);
  if (savedLang === "te" || savedLang === "en") {
    currentChatLang = savedLang;
  }
} catch (_) {
  currentChatLang = "en";
}

function t(enText, teText) {
  return currentChatLang === "te" ? teText : enText;
}

function getChatContainer() {
  return document.getElementById("chat-messages");
}

function toggleChat() {
  const chat = document.getElementById("chatbot-container");
  if (!chat) return;
  chat.classList.toggle("hidden");

  if (!chatbotInitialized && !chat.classList.contains("hidden")) {
    initChatbot();
    chatbotInitialized = true;
  }
}

// Called from existing onclick handler in home.html.
function startChat() {
  const chat = document.getElementById("chatbot-container");
  if (!chat) return;
  if (!chatbotInitialized && !chat.classList.contains("hidden")) {
    initChatbot();
    chatbotInitialized = true;
  }
}

function getDefaultSuggestions() {
  if (currentChatLang === "te") {
    return [
      "సేవలు",
      "ప్లాన్లు",
      "డాక్యుమెంట్ చెక్‌లిస్ట్",
      "కన్సల్టేషన్ బుక్ చేయండి",
      "WhatsApp చాట్"
    ];
  }
  return [
    "Services",
    "Plans",
    "Document Checklist",
    "Book Consultation",
    "WhatsApp Chat"
  ];
}

function updateLanguageControls() {
  const enBtn = document.getElementById("chat-lang-en");
  const teBtn = document.getElementById("chat-lang-te");
  if (enBtn) enBtn.classList.toggle("active", currentChatLang === "en");
  if (teBtn) teBtn.classList.toggle("active", currentChatLang === "te");

  const input = document.getElementById("chat-input");
  if (input) {
    input.placeholder = t("Type a message...", "మీ సందేశాన్ని టైప్ చేయండి...");
  }

  const sendBtn = document.getElementById("chat-send-btn");
  if (sendBtn) {
    sendBtn.innerText = t("Send", "పంపు");
  }
}

function setChatLanguage(lang, opts = {}) {
  const normalized = lang === "te" ? "te" : "en";
  const changed = normalized !== currentChatLang;
  currentChatLang = normalized;

  try {
    sessionStorage.setItem(CHAT_LANG_KEY, currentChatLang);
  } catch (_) {
    // Ignore storage issues silently.
  }

  updateLanguageControls();

  if (chatbotInitialized) {
    renderSuggestions(getDefaultSuggestions());
    if (changed && !opts.silent) {
      addBotMessage(
        currentChatLang === "te"
          ? "భాష తెలుగు కి మార్చబడింది. నేను మీకు సేవలు మరియు ప్లాన్లపై సహాయం చేస్తాను."
          : "Language switched to English. I can help you with services and plans."
      );
    }
  }
}

window.setChatLanguage = setChatLanguage;

function saveMessage(role, text) {
  try {
    const history = JSON.parse(sessionStorage.getItem(CHAT_HISTORY_KEY) || "[]");
    history.push({ role, text });
    sessionStorage.setItem(CHAT_HISTORY_KEY, JSON.stringify(history.slice(-40)));
  } catch (_) {
    // Ignore storage issues silently.
  }
}

function appendMessage(role, text) {
  const chat = getChatContainer();
  if (!chat) return;

  const div = document.createElement("div");
  div.className = role === "user" ? "user-msg" : "bot-msg";
  div.innerText = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function addBotMessage(text) {
  appendMessage("bot", text);
  saveMessage("bot", text);
}

function addUserMessage(text) {
  appendMessage("user", text);
  saveMessage("user", text);
}

function renderHistory() {
  try {
    const history = JSON.parse(sessionStorage.getItem(CHAT_HISTORY_KEY) || "[]");
    if (!Array.isArray(history) || history.length === 0) return false;
    history.forEach((item) => {
      if (item && typeof item.text === "string") {
        appendMessage(item.role === "user" ? "user" : "bot", item.text);
      }
    });
    return true;
  } catch (_) {
    return false;
  }
}

function showTyping() {
  const chat = getChatContainer();
  if (!chat) return;

  let typing = document.getElementById("bot-typing");
  if (typing) return;
  typing = document.createElement("div");
  typing.id = "bot-typing";
  typing.className = "bot-msg typing";
  typing.innerText = t("SV Accountax Crew is typing", "SV Accountax Crew టైప్ చేస్తోంది");
  chat.appendChild(typing);
  chat.scrollTop = chat.scrollHeight;
}

function hideTyping() {
  const typing = document.getElementById("bot-typing");
  if (typing) typing.remove();
}

function buildWhatsAppLink() {
  return `https://wa.me/${WHATSAPP_NUMBER}?text=Hi%20I%20need%20tax%20assistance`;
}

function quickItemType(label) {
  const lower = (label || "").toLowerCase().trim();
  if (
    lower.includes("whatsapp") ||
    lower.includes("వాట్సాప్")
  ) return "whatsapp";
  if (
    lower.includes("book consultation") ||
    lower.includes("consultation") ||
    lower.includes("callback") ||
    lower.includes("కన్సల్టేషన్")
  ) return "consultation";
  if (
    lower.includes("document checklist") ||
    lower.includes("checklist") ||
    lower.includes("చెక్‌లిస్ట్") ||
    lower.includes("డాక్యుమెంట్")
  ) return "checklist";
  return "text";
}

function mapSuggestionLabel(label) {
  const key = (label || "").trim().toLowerCase();
  if (currentChatLang !== "te") return label;

  const map = {
    "services": "సేవలు",
    "plans": "ప్లాన్లు",
    "document checklist": "డాక్యుమెంట్ చెక్‌లిస్ట్",
    "book consultation": "కన్సల్టేషన్ బుక్ చేయండి",
    "whatsapp chat": "WhatsApp చాట్",
    "contact": "సంప్రదింపు",
    "working hours": "పని గంటలు",
    "basic plan": "బేసిక్ ప్లాన్",
    "professional plan": "ప్రొఫెషనల్ ప్లాన్",
    "business plan": "బిజినెస్ ప్లాన్",
    "individual": "వ్యక్తిగతం",
    "business / startup": "బిజినెస్ / స్టార్టప్",
    "itr": "ITR",
    "gst": "GST",
    "tds": "TDS",
    "registrations": "రిజిస్ట్రేషన్స్",
    "accounting": "అకౌంటింగ్",
    "roc": "ROC"
  };
  return map[key] || label;
}

function normalizeOutgoingMessage(message) {
  const input = (message || "").trim();
  const lower = input.toLowerCase();

  const teluguMap = [
    ["సేవలు", "services"],
    ["ప్లాన్", "plans"],
    ["డాక్యుమెంట్", "document checklist"],
    ["చెక్‌లిస్ట్", "document checklist"],
    ["కన్సల్టేషన్", "book consultation"],
    ["వాట్సాప్", "whatsapp"],
    ["సంప్రదింపు", "contact"],
    ["పని గంటలు", "working hours"],
    ["వ్యక్తిగతం", "individual"],
    ["బిజినెస్", "business / startup"]
  ];

  for (const pair of teluguMap) {
    if (lower.includes(pair[0])) return pair[1];
  }
  return input;
}

function renderSuggestions(suggestions) {
  const container = document.getElementById("suggestions");
  if (!container) return;
  container.innerHTML = "";

  if (!Array.isArray(suggestions) || suggestions.length === 0) return;

  const seen = new Set();
  suggestions.forEach((label) => {
    if (!label || typeof label !== "string") return;
    const trimmed = label.trim();
    const key = trimmed.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);

    const shownLabel = mapSuggestionLabel(trimmed);
    const type = quickItemType(shownLabel);

    if (type === "whatsapp") {
      const a = document.createElement("a");
      a.href = buildWhatsAppLink();
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.className = "quick-btn";
      a.innerText = t("Chat on WhatsApp", "WhatsAppలో చాట్ చేయండి");
      container.appendChild(a);
      return;
    }

    if (type === "consultation") {
      const a = document.createElement("a");
      a.href = "/consultation";
      a.className = "quick-btn";
      a.innerText = t("Book Consultation", "కన్సల్టేషన్ బుక్ చేయండి");
      container.appendChild(a);
      return;
    }

    if (type === "checklist") {
      const a = document.createElement("a");
      a.href = "/document-checklist";
      a.className = "quick-btn";
      a.innerText = t("Document Checklist", "డాక్యుమెంట్ చెక్‌లిస్ట్");
      container.appendChild(a);
      return;
    }

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quick-btn";
    btn.innerText = shownLabel;
    btn.onclick = () => sendToBot(shownLabel);
    container.appendChild(btn);
  });
}

function sendToBot(message) {
  if (botBusy) return;
  botBusy = true;
  showTyping();

  const normalizedMessage = normalizeOutgoingMessage(message);

  fetch("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: normalizedMessage, lang: currentChatLang })
  })
    .then((res) => res.json())
    .then((data) => {
      addBotMessage(data.reply || t("Please contact us on WhatsApp for assistance.", "దయచేసి సహాయం కోసం WhatsApp లో సంప్రదించండి."));
      renderSuggestions(data.suggestions || []);
    })
    .catch(() => {
      addBotMessage(
        t(
          "I could not process that right now.\nPlease contact us on WhatsApp or call +91 9676359019.",
          "ఇప్పుడు ఆ అభ్యర్థనను ప్రాసెస్ చేయలేకపోయాను.\nదయచేసి WhatsApp లో లేదా +91 9676359019 కి కాల్ చేసి సంప్రదించండి."
        )
      );
      renderSuggestions(["WhatsApp Chat", "Contact", "Book Consultation"]);
    })
    .finally(() => {
      hideTyping();
      botBusy = false;
    });
}

function sendMessage() {
  if (botBusy) return;
  const input = document.getElementById("chat-input");
  if (!input) return;
  const message = input.value.trim();
  if (!message) return;

  addUserMessage(message);
  input.value = "";
  sendToBot(message);
}

function initChatbot() {
  updateLanguageControls();

  const restored = renderHistory();
  if (!restored) {
    addBotMessage(
      t(
        "Hi, welcome to SV Accountax Crew.\n\nI am your virtual receptionist. I can help with services, plans, GST, ITR, registrations, and contact details.",
        "హాయ్, SV Accountax Crew కు స్వాగతం.\n\nనేను మీ వర్చువల్ రిసెప్షనిస్ట్‌ను. సేవలు, ప్లాన్లు, GST, ITR, రిజిస్ట్రేషన్స్, కాంటాక్ట్ వివరాల్లో మీకు సహాయం చేస్తాను."
      )
    );
  }

  renderSuggestions(getDefaultSuggestions());
}

updateLanguageControls();
