import os
import json
import logging
import datetime
import httpx
from typing import Dict, Any, Optional
from dotenv import load_dotenv

from models import AnalysisRequest, AnalysisResponse
from threat_engine import threat_engine

# Load environment variables
load_dotenv()

logger = logging.getLogger("scamshield.analyzer")

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
GEMINI_FALLBACK_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

SYSTEM_PROMPT = """You are SCAMSHIELD AI, a world-class cybersecurity forensic investigator and threat analyst specializing in social engineering, phishing, financial fraud, impersonation attacks, and digital extortion.

Your objective: Thoroughly analyze the user's provided message and return a strictly structured JSON response evaluating its risk.

Scam Vectors to investigate:
1. Urgency / Panic Induction: Deadlines ("24 hours", "immediate action required", "account blocked tonight").
2. Inverted Financial Traps: Asking someone to enter a UPI PIN or scan a QR code to RECEIVE money (in UPI, PIN is ONLY used to SEND money).
3. Credential & Identity Theft: Asking for OTP, PIN, passwords, PAN/Aadhaar card updates, KYC verification.
4. Deceptive URLs & Phishing: Suspicious domains, free hosting (ngrok, firebaseapp), IP addresses, URL shorteners (bit.ly), lookalike domains (sbi-kyc.xyz).
5. False Authority & Extortion: Posing as Police, CBI, Customs, FedEx, Bank Managers, Income Tax officials, threatening arrest or fines ("Digital Arrest").
6. Unrealistic Rewards & Lures: High-paying daily part-time tasks (liking YouTube videos, Telegram jobs), unverified lotteries (KBC, Amazon prize).
7. Advance Fee Traps: Asking for a small tax, clearance, or registration fee before releasing funds.
8. Legitimate Messages: Legitimate bank OTPs containing explicit warnings ("NEVER share your OTP with anyone"), standard non-urgent shipping updates, transactional receipts with official contact info.

You MUST respond with pure JSON matching this exact structure:
{
  "riskLevel": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
  "riskScore": number (0 to 100),
  "category": "Phishing" | "UPI / Payment Fraud" | "Bank Impersonation" | "Fake Job / Task Scam" | "Digital Arrest / Police Extortion" | "Lottery / Advance Fee Fraud" | "Social Engineering" | "Legitimate Notification",
  "summary": "Clear, concise 2-sentence forensic summary for non-technical users explaining what this message is doing.",
  "redFlags": [
    {
      "title": "Short title of warning",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "description": "Why this is dangerous",
      "quote": "Exact substring from user text"
    }
  ],
  "whyFlagged": [
    {
      "factor": "Name of social engineering or technical threat vector",
      "explanation": "Forensic rationale explaining why attackers use this tactic",
      "detectedQuote": "Exact substring from user text"
    }
  ],
  "recommendedActions": [
    "Practical safety advice step 1",
    "Practical safety advice step 2"
  ],
  "detectedPhrases": [
    {
      "phrase": "Exact substring from text to highlight",
      "reason": "Why this specific phrase is dangerous",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    }
  ],
  "extractedEntities": {
    "urls": ["http://..."],
    "phoneNumbers": ["+91..."],
    "emails": ["user@example.com"],
    "monetaryAmounts": ["Rs. 24,999"],
    "impersonatedEntity": "HDFC Bank / Mumbai Customs / Telegram HR or null"
  },
  "confidence": number between 0.80 and 0.99,
  "isLegitimate": boolean
}
"""

async def analyze_with_gemini(text: str, sender: Optional[str], channel: Optional[str], api_key: str) -> Optional[Dict[str, Any]]:
    """Calls Google Gemini API with JSON mode."""
    headers = {"Content-Type": "application/json"}
    user_content = f"Sender: {sender or 'Not provided'}\nChannel: {channel or 'Not specified'}\nMessage Content:\n```\n{text}\n```"

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": user_content}
                ]
            }
        ],
        "systemInstruction": {
            "parts": [
                {"text": SYSTEM_PROMPT}
            ]
        },
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1
        }
    }

    urls_to_try = [
        f"{GEMINI_API_URL}?key={api_key}",
        f"{GEMINI_FALLBACK_URL}?key={api_key}"
    ]

    async with httpx.AsyncClient(timeout=15.0) as client:
        for url in urls_to_try:
            try:
                response = await client.post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            raw_json = parts[0].get("text", "{}")
                            parsed = json.loads(raw_json)
                            # Ensure timestamp and engine
                            parsed["engineUsed"] = "Gemini 2.5 Flash"
                            parsed["analyzedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                            return parsed
                else:
                    logger.warning(f"Gemini API returned status {response.status_code}: {response.text}")
            except Exception as e:
                logger.warning(f"Error calling Gemini endpoint {url}: {e}")

    return None

async def analyze_message(request: AnalysisRequest) -> Dict[str, Any]:
    """
    Primary analysis orchestrator.
    Attempts live Gemini analysis if API key is present; otherwise seamlessly
    executes the ScamShield Heuristic Defense Engine.
    """
    text = request.text.strip()
    sender = request.sender.strip() if request.sender else None
    channel = request.channel or "Unknown"

    # Priority 1: User-supplied key in request
    # Priority 2: Server environment variable
    api_key = request.apiKey or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    result = None

    if api_key and len(api_key.strip()) > 10:
        logger.info("Attempting analysis using Gemini AI...")
        result = await analyze_with_gemini(text, sender, channel, api_key.strip())
        if result:
            # Augment with domain intelligence from threat engine
            extracted_urls = result.get("extractedEntities", {}).get("urls", [])
            domain_reports = [threat_engine.analyze_domain(u) for u in extracted_urls]
            if "extractedEntities" in result:
                result["extractedEntities"]["suspiciousDomains"] = domain_reports
            return result
        else:
            logger.warning("Gemini AI request failed or was unavailable; switching to Local Heuristic Engine.")

    # Fallback to local heuristic threat engine
    logger.info("Running ScamShield Heuristic Defense Engine...")
    result = threat_engine.analyze(text, sender, channel)
    return result
