from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Dict
import re
import time
import requests

app = FastAPI(title="GUVI Agentic Honeypot")

# ================= CONFIG =================
API_KEY = "mysecretkey"
GUVI_CALLBACK = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

SCAM_KEYWORDS = [
    "blocked", "kyc", "otp", "refund", "verify",
    "urgent", "suspended", "click", "account"
]

# ================= MEMORY =================
sessions: Dict[str, Dict] = {}

# ================= MODELS =================
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: str = None
    language: str = None
    locale: str = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Metadata = None

# ================= HELPERS =================
def is_scam(text: str) -> bool:
    count = sum(word in text.lower() for word in SCAM_KEYWORDS)
    return count >= 2

def extract_intelligence(text: str, memory: dict):
    memory["upiIds"] += re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", text)
    memory["bankAccounts"] += re.findall(r"\b\d{9,18}\b", text)
    memory["phishingLinks"] += re.findall(r"https?:\/\/[^\s]+", text)
    memory["phoneNumbers"] += re.findall(r"\+91\d{10}", text)

    for word in SCAM_KEYWORDS:
        if word in text.lower():
            memory["suspiciousKeywords"].append(word)

def agent_reply(turn: int) -> str:
    replies = [
        "Why will my account be blocked?",
        "I don’t understand, can you explain slowly?",
        "You said verification, how do I do it?",
        "Should I send details from Google Pay?",
        "Bank app is asking beneficiary details, what to enter?"
    ]
    return replies[min(turn, len(replies) - 1)]

def send_final_callback(session_id: str, memory: dict):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": memory["turns"],
        "extractedIntelligence": {
            "bankAccounts": list(set(memory["bankAccounts"])),
            "upiIds": list(set(memory["upiIds"])),
            "phishingLinks": list(set(memory["phishingLinks"])),
            "phoneNumbers": list(set(memory["phoneNumbers"])),
            "suspiciousKeywords": list(set(memory["suspiciousKeywords"]))
        },
        "agentNotes": "Used urgency and verification scam pattern"
    }

    try:
        requests.post(GUVI_CALLBACK, json=payload, timeout=5)
    except:
        pass  # Do not crash API

# ================= API =================
@app.post("/honeypot")
def honeypot(
    data: HoneypotRequest,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    sid = data.sessionId

    if sid not in sessions:
        sessions[sid] = {
            "turns": 0,
            "scamDetected": False,
            "upiIds": [],
            "bankAccounts": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": [],
            "finalSent": False
        }

    memory = sessions[sid]
    memory["turns"] += 1

    # Detect scam
    if is_scam(data.message.text):
        memory["scamDetected"] = True

    # Extract intelligence
    extract_intelligence(data.message.text, memory)

    # Agent reply
    reply = "Okay"
    if memory["scamDetected"]:
        reply = agent_reply(memory["turns"])

    # FINAL CALLBACK condition
    if memory["scamDetected"] and memory["turns"] >= 5 and not memory["finalSent"]:
        send_final_callback(sid, memory)
        memory["finalSent"] = True

    return {
        "status": "success",
        "reply": reply
    }
