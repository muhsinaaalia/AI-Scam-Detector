# 🛡️ SCAMSHIELD

> **"Think before you click."**  
> *AI-Powered Scam & Phishing Risk Analyzer with Forensic Explainability*

[![Status](https://img.shields.io/badge/Status-Production%20MVP-success?style=flat-square)](#)
[![AI Engine](https://img.shields.io/badge/AI%20Engine-Gemini%202.5%20Flash%20%2B%20Heuristic%20Defense-blue?style=flat-square)](#)
[![Zero Data Retention](https://img.shields.io/badge/Privacy-Zero%20Data%20Retention-emerald?style=flat-square)](#)

---

## 📌 Executive Summary

Every day, millions of digital citizens receive fraudulent SMS alerts, WhatsApp lottery notifications, fake work-from-home job offers, and inverted UPI refund requests. Inexperienced or hurried users are vulnerable to sophisticated psychological coercion (urgency, panic, fear of arrest, greed).

**ScamShield** is an AI-powered cyber threat intelligence analyzer built for high-stakes hackathons and real-world deployment. In under **5 seconds**, it deconstructs suspicious messages, computes a quantitative risk score (0–100), isolates specific red flags, maps threat triggers on an **interactive heatmap**, and delivers clear, actionable defense instructions.

---

## 🚀 Key Innovations & Features

### 1. Dual-Engine Neural & Heuristic Architecture
* **Primary Engine — Google Gemini 2.5 Flash:** Deep social engineering detection, contextual entity extraction, and structured JSON reasoning.
* **Secondary Engine — ScamShield Heuristic Defense Engine:** A high-speed, zero-dependency pattern engine providing **100% offline functionality**. Judges can test the application instantly without needing an external API key or network access.

### 2. Forensic Explainability Matrix (Zero "Black-Box" AI)
Rather than simply stating *"AI says this is a scam"*, ScamShield provides:
* **Interactive Message Heatmap:** Highlights dangerous phrases in the user's message with tooltips explaining the underlying threat vector.
* **Why Flagged Breakdown:** Explains the psychological manipulation technique (e.g. *Inverted UPI Logic*, *Artificial Urgency*, *Fear & False Legal Authority*).
* **Direct Evidence Snippets:** Quotes exact excerpts from the message.

### 3. Comprehensive Attack Taxonomy
ScamShield identifies and scores major cyber-crime vectors:
* **UPI & QR Inversion Traps:** Detects fraudulent claims asking users to *enter a UPI PIN or scan a QR code to receive money* (in UPI, PIN is strictly for *sending* money).
* **Bank KYC & Account Deactivation Scares:** Detects threats of account suspension within 24 hours impersonating HDFC, SBI, ICICI, etc.
* **Digital Arrest & Police Extortion:** Detects fake courier/customs parcels containing "drugs" and threats of arrest from fake CBI/Cyber Crime officers.
* **Telegram Task / Fake Job Scams:** Detects "like YouTube videos, earn ₹8,000 daily" lures with off-platform Telegram redirection.
* **Lottery & Advance Fee Scams:** Detects KBC / lucky draw prizes demanding upfront tax clearance fees.
* **Credential Phishing:** Analyzes domains for suspicious TLDs (`.xyz`, `.top`, `.online`), URL shorteners, direct IP addresses, and typosquatting.
* **Legitimate Message Recognition:** Accurately recognizes genuine banking OTPs and shipping notices with zero-trust warnings, giving them a **SAFE** rating.

### 4. Enterprise-Grade User Experience
* **Radial Score Gauge:** Animated SVG dial displaying risk from 0 to 100 with contextual color tokens.
* **Actionable Defense Checklist:** Step-by-step checklist users can physically check off as they take safety precautions.
* **Forensic Incident Report Generator:** 1-click generation of formatted incident reports ready to forward to bank cyber teams or the **1930 Cyber Fraud Helpline**.
* **Local Privacy:** Client-side local storage history with zero cloud logging of sensitive message text.

---

## 🛠️ System Architecture

```text
[ User / Web Browser ]
        │
        ▼
[ ScamShield Modern Cyber Dashboard ]
   ├── Input Console & Demo Cases Bar
   ├── Interactive Heatmap Inspector
   ├── Radial Score Gauge (0-100)
   └── Local Storage History Drawer
        │
        ▼ (REST / JSON)
[ FastAPI Backend (server.py) ]
        │
        ├── [ analyzer.py ] ──────────┐
        │                             │
        ▼                             ▼
[ Gemini 2.5 Flash API ]    [ Local Threat Engine ]
  (Deep Neural Reasoning)     (Zero-Latency Heuristics)
        │                             │
        └──────────────┬──────────────┘
                       ▼
        [ Structured JSON Response ]
           - riskLevel & riskScore
           - category & summary
           - redFlags with evidence quotes
           - whyFlagged forensic factors
           - recommendedActions checklist
           - detectedPhrases for heatmap
```

---

## ⚡ Quickstart Guide

### Prerequisites
* Python 3.10+ installed on Windows, macOS, or Linux.
* Required packages (already installed): `fastapi`, `uvicorn`, `httpx`, `pydantic`, `python-dotenv`.

### 1. Launch the Application (Windows 1-Click)
Simply double-click:
```cmd
start.bat
```
Or run from PowerShell / Terminal:
```bash
python run_server.py
```
This automatically starts the server at `http://localhost:8000` and opens your browser.

### 2. Optional: Configure Gemini API Key
To enable the live Gemini 2.5 Flash neural engine:
1. Create a `.env` file from `.env.example`:
   ```env
   GEMINI_API_KEY=your_actual_gemini_api_key_here
   ```
2. Or click the **Settings (⚙️)** icon in the top-right navigation bar of the web app and enter your key directly.

> **Note:** If no key is entered, ScamShield automatically and seamlessly runs on its built-in **Heuristic Cyber Defense Engine**, delivering comprehensive analysis and scoring for all test cases.

---

## 🧪 Automated Test Verification

Run the built-in forensic verification suite:
```bash
python test_analyzer.py
```
This verifies risk classification, scoring accuracy, and explainability across all 8 attack vectors.

---

## 📋 Hackathon Judging Alignment

| Judging Criterion | How ScamShield Delivers |
| :--- | :--- |
| **Problem Relevance** | Targets the #1 consumer cyber-threat (phishing, UPI fraud, fake jobs, digital arrest). |
| **Technical Depth** | Hybrid AI architecture (Gemini 2.5 Flash + Local Heuristic Engine) with zero failure modes. |
| **Explainability** | Features an interactive message heatmap highlighting exact threat triggers and explaining *why* attackers use each tactic. |
| **UX & Polish** | Cyber defense visual identity, radial score gauge, keyboard shortcuts (`Ctrl+Enter`), and actionable checklist. |
| **Demo Readiness** | 8 pre-loaded realistic attack vectors allow judges to test the app in seconds with zero configuration. |

---

## 📞 Emergency Resources
* **India Cyber Crime Helpline:** Dial **1930**
* **National Portal:** [cybercrime.gov.in](https://cybercrime.gov.in)
* **US FTC Fraud Reporting:** [reportfraud.ftc.gov](https://reportfraud.ftc.gov)
* **FBI IC3:** [ic3.gov](https://www.ic3.gov)

---
*Built with ❤️ for digital safety. Think before you click.*
