import re
import datetime
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse

class ThreatIntelligenceEngine:
    """
    Forensic Heuristic Threat Intelligence Engine for ScamShield.
    Detects scam patterns, social engineering heuristics, suspicious URLs,
    financial inversion traps, and psychological coercion techniques.
    """

    SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", 
        "tiny.cc", "rebrand.ly", "shorturl.at", "ow.ly", "buff.ly", "v.gd"
    }

    SUSPICIOUS_TLDS = {
        "xyz", "top", "buzz", "club", "work", "click", "cam", "live", 
        "loan", "cfd", "gq", "tk", "ml", "fit", "rest", "online", "site",
        "icu", "monster", "fun", "uno", "link"
    }

    FREE_HOSTS = {
        "ngrok.app", "ngrok-free.app", "firebaseapp.com", "web.app", 
        "vercel.app", "pages.dev", "000webhostapp.com", "blogspot.com", "glitch.me"
    }

    LEGITIMATE_DOMAINS = {
        "amazon.in", "amazon.com", "flipkart.com", "sbi.co.in", "hdfcbank.com", 
        "icicibank.com", "axisbank.com", "google.com", "apple.com", "microsoft.com",
        "uber.com", "zomato.com", "swiggy.com", "phonepe.com", "paytm.com"
    }

    def __init__(self):
        # Precompile regexes
        self.url_regex = re.compile(
            r'(?:https?://|www\.)[^\s<>"\'{}|\\^`]+',
            re.IGNORECASE
        )
        self.phone_regex = re.compile(
            r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,5}\)?[-.\s]?\d{3,5}[-.\s]?\d{3,5}',
            re.IGNORECASE
        )
        self.email_regex = re.compile(
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            re.IGNORECASE
        )
        self.money_regex = re.compile(
            r'(?:(?:Rs\.?|INR|₹|\$|€|£)\s*[\d,]+(?:\.\d{2})?|[\d,]+\s*(?:lakhs?|crores?|rupees|USD))',
            re.IGNORECASE
        )

    def extract_urls(self, text: str) -> List[str]:
        urls = self.url_regex.findall(text)
        cleaned = []
        for u in urls:
            u = u.rstrip('.,;:)!?"\'')
            if not u.startswith("http"):
                u = "http://" + u
            cleaned.append(u)
        return list(set(cleaned))

    def analyze_domain(self, url: str) -> Dict[str, Any]:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ":" in domain:
                domain = domain.split(":")[0]

            parts = domain.split(".")
            tld = parts[-1] if len(parts) > 1 else ""

            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
            is_shortener = domain in self.SHORTENERS or any(domain.endswith("." + s) for s in self.SHORTENERS)
            is_suspicious_tld = tld in self.SUSPICIOUS_TLDS
            is_free_host = any(domain.endswith(host) for host in self.FREE_HOSTS)
            is_legit = domain in self.LEGITIMATE_DOMAINS or any(domain.endswith("." + l) for l in self.LEGITIMATE_DOMAINS)

            risk_points = 0
            reasons = []

            if is_ip:
                risk_points += 45
                reasons.append(f"Direct IP address URL ({domain}) disguises the true hosting server")
            if is_shortener:
                risk_points += 30
                reasons.append(f"URL shortener ({domain}) hides destination endpoint from security scanners")
            if is_suspicious_tld:
                risk_points += 35
                reasons.append(f"High-risk top-level domain (.{tld}) frequently used in disposable phishing infrastructure")
            if is_free_host:
                risk_points += 25
                reasons.append(f"Free cloud tunnel/hosting service ({domain}) commonly abused for ephemeral phishing sites")

            # Brand typo / imitation check
            brands = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "amazon", "netflix", "apple", "google", "instagram"]
            for brand in brands:
                if brand in domain and not is_legit:
                    risk_points += 40
                    reasons.append(f"Domain appears to impersonate '{brand.upper()}' on an unauthorized non-official domain ({domain})")
                    break

            return {
                "url": url,
                "domain": domain,
                "tld": tld,
                "is_ip": is_ip,
                "is_shortener": is_shortener,
                "is_suspicious_tld": is_suspicious_tld,
                "is_free_host": is_free_host,
                "is_legitimate_known": is_legit,
                "risk_points": risk_points,
                "reasons": reasons
            }
        except Exception:
            return {"url": url, "domain": "unknown", "risk_points": 20, "reasons": ["Malformed URL"]}

    def analyze(self, text: str, sender: str = None, channel: str = "Unknown") -> Dict[str, Any]:
        text_lower = text.lower()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Extract entities
        urls = self.extract_urls(text)
        phone_matches = self.phone_regex.findall(text)
        email_matches = self.email_regex.findall(text)
        money_matches = self.money_regex.findall(text)

        domain_reports = [self.analyze_domain(u) for u in urls]

        red_flags: List[Dict[str, Any]] = []
        why_flagged: List[Dict[str, Any]] = []
        detected_phrases: List[Dict[str, str]] = []
        recommended_actions: List[str] = []

        total_risk_score = 0
        categories_detected = []
        impersonated_brand = None

        # -------------------------------------------------------------
        # 1. CHECK FOR LEGITIMATE SAFETY SIGNALS (Negative weights)
        # -------------------------------------------------------------
        safety_bonus = 0
        legit_otp_warning = False

        if any(phrase in text_lower for phrase in [
            "do not share this otp", "never share your otp", "bank never asks for otp",
            "do not share your password", "do not share with anyone", "strictly confidential"
        ]):
            legit_otp_warning = True
            safety_bonus += 40

        if any(phrase in text_lower for phrase in [
            "sms block to", "call toll free", "avail bal:", "available balance",
            "debited for rs", "credited to a/c", "prepaid package", "no payment is required"
        ]) and not any(urgent in text_lower for urgent in ["immediately", "24 hours", "suspended", "blocked", "lottery"]):
            safety_bonus += 30

        # -------------------------------------------------------------
        # 2. UPI / PAYMENT INVERSION FRAUD CHECK (Extremely critical)
        # -------------------------------------------------------------
        upi_pin_to_receive = bool(
            re.search(r'(?:scan\s*(?:this\s*)?qr|enter\s*(?:your\s*)?(?:4|6)?[-\s]*digit\s*upi\s*pin|enter\s*pin\s*to\s*(?:receive|accept|credit|get))', text_lower)
        )
        upi_cashback_refund = bool(
            re.search(r'(?:refund\s*of\s*(?:rs|₹)|received\s*a\s*refund|cashback\s*of\s*(?:rs|₹)|phonepe\s*cashback|gpay\s*reward)', text_lower)
        )

        if upi_pin_to_receive:
            total_risk_score += 65
            categories_detected.append("UPI / Payment Fraud")
            match = re.search(r'(scan\s*[^.\n]*|enter\s*[^.\n]*pin[^.\n]*)', text, re.IGNORECASE)
            quote = match.group(0) if match else "enter UPI PIN to receive money"
            red_flags.append({
                "title": "UPI Financial Inversion Trap (Critical)",
                "severity": "CRITICAL",
                "description": "The message falsely asks you to scan a QR code or enter your UPI PIN to RECEIVE funds.",
                "quote": quote
            })
            why_flagged.append({
                "factor": "Inverted UPI Payment Logic",
                "explanation": "In real UPI banking architecture, entering your UPI PIN or scanning a merchant QR code ALWAYS debits money from your account. You NEVER need to enter a PIN to receive incoming money or refunds.",
                "detectedQuote": quote
            })
            detected_phrases.append({
                "phrase": quote,
                "reason": "Dangerous deception: entering PIN will authorize a deduction, not a deposit.",
                "severity": "CRITICAL"
            })
            recommended_actions.append("DO NOT scan any QR code or enter your UPI PIN. You never enter a PIN to receive money.")
            recommended_actions.append("Block the sender immediately and report the UPI ID on your payment app (Google Pay / PhonePe / Paytm).")

        if upi_cashback_refund:
            total_risk_score += 30
            if "UPI / Payment Fraud" not in categories_detected:
                categories_detected.append("UPI / Payment Fraud")
            red_flags.append({
                "title": "Unsolicited Refund / Cashback Lure",
                "severity": "HIGH",
                "description": "Offers sudden refunds or cashbacks requiring user action, a common entry point for payment fraud.",
                "quote": money_matches[0] if money_matches else "refund of money"
            })
            detected_phrases.append({
                "phrase": money_matches[0] if money_matches else "refund",
                "reason": "Baiting tactic offering unearned funds to trigger excitement.",
                "severity": "HIGH"
            })

        # -------------------------------------------------------------
        # 3. BANK KYC & ACCOUNT DEACTIVATION SCARE
        # -------------------------------------------------------------
        kyc_phrases = [
            "kyc verification", "kyc pending", "account has been suspended", "account suspended",
            "permanently blocked", "pan card not linked", "ebill disconnection", "power will be disconnected",
            "yono account", "netbanking deactivated", "credit card reward points"
        ]
        matched_kyc = [p for p in kyc_phrases if p in text_lower]

        if matched_kyc:
            total_risk_score += 45
            categories_detected.append("Bank Impersonation")
            # Identify which bank
            for b in ["sbi", "hdfc", "icici", "axis", "pnb", "bob", "kotak"]:
                if b in text_lower:
                    impersonated_brand = b.upper()
                    break

            quote = matched_kyc[0]
            red_flags.append({
                "title": "Fake Account Suspension & KYC Threat",
                "severity": "HIGH",
                "description": "Impersonates bank or utility authority threatening service suspension if personal/financial data is not updated immediately.",
                "quote": quote
            })
            why_flagged.append({
                "factor": "Fear & Authority Coercion",
                "explanation": "Attackers induce panic by threatening total loss of bank account access or utility shutoff, compelling victims to bypass standard verification protocols.",
                "detectedQuote": quote
            })
            detected_phrases.append({
                "phrase": quote,
                "reason": "Scare tactic designed to induce panic and force hurried compliance.",
                "severity": "HIGH"
            })
            recommended_actions.append(f"Never click links claiming to update KYC. Visit your bank branch or use the official mobile app directly.")
            recommended_actions.append("Remember that banks in India and internationally never send SMS links to update PAN or Aadhaar.")

        # -------------------------------------------------------------
        # 4. DIGITAL ARREST / POLICE / CUSTOMS EXTORTION
        # -------------------------------------------------------------
        arrest_phrases = [
            "customs", "narcotics", "fake passports", "arrest warrant", "cbi", "ed",
            "cyber crime branch", "police arrest", "illegal parcel", "fedex express",
            "parcel detained", "seized by", "skype", "inspector"
        ]
        matched_arrest = [p for p in arrest_phrases if p in text_lower]

        if len(matched_arrest) >= 2:
            total_risk_score += 75
            categories_detected.append("Digital Arrest / Police Extortion")
            quote = ", ".join(matched_arrest[:3])
            red_flags.append({
                "title": "Law Enforcement Impersonation & Digital Arrest",
                "severity": "CRITICAL",
                "description": "Fabricates claims of illegal parcels, drugs, or arrest warrants to extort payments via fear.",
                "quote": quote
            })
            why_flagged.append({
                "factor": "Severe Intimidation & False Legal Authority",
                "explanation": "This matches the widespread 'Digital Arrest' scam where criminals pose as FedEx/Customs/Police officials demanding video calls or clearance bribes. Official police forces never conduct interrogations or demand money via WhatsApp/Skype.",
                "detectedQuote": quote
            })
            detected_phrases.append({
                "phrase": quote,
                "reason": "Intimidation tactic to force immediate panic payment or video entrapment.",
                "severity": "CRITICAL"
            })
            recommended_actions.append("Do NOT join any video call (Skype/WhatsApp) or send any clearance fees.")
            recommended_actions.append("Immediately report this incident to the National Cyber Crime Reporting Portal (call 1930 in India or visit cybercrime.gov.in).")

        # -------------------------------------------------------------
        # 5. WORK-FROM-HOME / TASK / TELEGRAM JOB SCAM
        # -------------------------------------------------------------
        job_phrases = [
            "part-time work", "part time work", "like youtube video", "earn 3000", "earn 5000",
            "earn 8000", "daily payout", "telegram hr", "telegram:", "@", "global media hr",
            "work from home opportunities", "prepaid task", "crypto task"
        ]
        matched_job = [p for p in job_phrases if p in text_lower]

        if len(matched_job) >= 2:
            job_score = 55
            if any(t in text_lower for t in ["telegram", "@", "telegram:"]):
                job_score += 20
            if any(t in text_lower for t in ["daily", "per task", "instant payout", "earn 3000", "earn 8000"]):
                job_score += 15
            total_risk_score += job_score
            categories_detected.append("Fake Job / Task Scam")
            quote = matched_job[0]
            red_flags.append({
                "title": "Unrealistic Part-Time Job / Task Lure",
                "severity": "HIGH",
                "description": "Promises high daily income for trivial tasks (e.g. liking videos) and redirects communications to Telegram.",
                "quote": quote
            })
            why_flagged.append({
                "factor": "Financial Greed & Off-Platform Telegram Redirection",
                "explanation": "Scammers offer small initial payouts for simple tasks to build false trust, then trick victims into paying large 'prepaid deposits' or 'crypto investment tasks' to release their earned balance.",
                "detectedQuote": quote
            })
            detected_phrases.append({
                "phrase": quote,
                "reason": "Classic task-based recruitment scam vector targeting easy earnings.",
                "severity": "HIGH"
            })
            recommended_actions.append("Do not contact recruitment managers on Telegram or WhatsApp.")
            recommended_actions.append("Never pay any registration fee, security deposit, or task recharge fee for employment.")

        # -------------------------------------------------------------
        # 6. PRIZE / LOTTERY / ADVANCE FEE SCAM
        # -------------------------------------------------------------
        lottery_phrases = [
            "congratulations! your", "congratulations", "won 1st prize", "won 25,00,000",
            "kbc lucky draw", "kbc", "iphone 16", "lucky draw", "tax clearance certificate",
            "claim your prize", "delivery fee to claim"
        ]
        matched_lottery = [p for p in lottery_phrases if p in text_lower]

        if len(matched_lottery) >= 2:
            lottery_score = 55
            if any(t in text_lower for t in ["tax clearance", "upi id:", "send rs", "within 2 hours"]):
                lottery_score += 25
            total_risk_score += lottery_score
            categories_detected.append("Lottery / Advance Fee Fraud")
            quote = matched_lottery[0]
            red_flags.append({
                "title": "Unsolicited Lottery / Prize Claim Trap",
                "severity": "HIGH",
                "description": "Claims you won a massive lottery or gift you never entered, asking for an upfront clearance or tax fee.",
                "quote": quote
            })
            why_flagged.append({
                "factor": "Advance Fee Social Engineering",
                "explanation": "A classic Advance Fee 419 scheme: the victim is told they won millions, but must transfer a small fee (e.g. ₹4,500) to 'release' the funds. The prize does not exist.",
                "detectedQuote": quote
            })
            detected_phrases.append({
                "phrase": quote,
                "reason": "Phony prize bait designed to extract upfront advance fees.",
                "severity": "HIGH"
            })
            recommended_actions.append("Ignore this message completely. Genuine lotteries never require advance tax payments via UPI.")
            recommended_actions.append("Block the phone number and report it as spam.")

        # -------------------------------------------------------------
        # 7. PHISHING / CREDENTIAL HARVESTING / URGENCY
        # -------------------------------------------------------------
        phishing_phrases = [
            "unusual login", "confirm your credentials", "verify your identity", "reset your password",
            "avoid permanent account deletion", "within 12 hours", "within 24 hours", "click immediately",
            "act now", "urgent", "security alert"
        ]
        matched_phishing = [p for p in phishing_phrases if p in text_lower]

        if matched_phishing:
            total_risk_score += 35
            if not categories_detected:
                categories_detected.append("Phishing / Credential Theft")
            quote = matched_phishing[0]
            red_flags.append({
                "title": "Artificial Urgency & Deadline Manipulation",
                "severity": "HIGH",
                "description": "Imposes an arbitrary deadline (e.g., 24 hours) to force impulsive action before the victim can verify authenticity.",
                "quote": quote
            })
            why_flagged.append({
                "factor": "Artificial Urgency Trigger",
                "explanation": "Social engineers systematically manufacture time pressure so victims panic and click without verifying the sender or domain authenticity.",
                "detectedQuote": quote
            })
            detected_phrases.append({
                "phrase": quote,
                "reason": "High-pressure urgency trigger designed to impair rational skepticism.",
                "severity": "HIGH"
            })

        # -------------------------------------------------------------
        # 8. SUSPICIOUS DOMAIN / URL RISKS
        # -------------------------------------------------------------
        for report in domain_reports:
            if report.get("risk_points", 0) > 0:
                total_risk_score += report["risk_points"]
                for reason in report.get("reasons", []):
                    red_flags.append({
                        "title": "Malicious or Deceptive URL Detected",
                        "severity": "HIGH",
                        "description": reason,
                        "quote": report["url"]
                    })
                    why_flagged.append({
                        "factor": "Deceptive Web Link",
                        "explanation": f"The link points to '{report['domain']}'. {reason}",
                        "detectedQuote": report["url"]
                    })
                    detected_phrases.append({
                        "phrase": report["url"],
                        "reason": reason,
                        "severity": "HIGH"
                    })
                recommended_actions.append(f"DO NOT click the link ({report['url']}). It does not belong to any verified official organization.")

        # Apply safety deductions
        if legit_otp_warning and not upi_pin_to_receive and not matched_arrest:
            total_risk_score = max(5, total_risk_score - safety_bonus)
            if total_risk_score < 25:
                categories_detected = ["Legitimate Notification"]
                why_flagged.append({
                    "factor": "Legitimate Security Warnings Present",
                    "explanation": "The message follows standard zero-trust banking hygiene by warning the user never to share their OTP or PIN with anyone, including bank staff.",
                    "detectedQuote": "NEVER share your OTP or PIN with anyone"
                })

        # Calculate final risk score clamped between 0 and 100
        final_score = min(99, max(5, total_risk_score))
        if legit_otp_warning and len(red_flags) == 0:
            final_score = 6

        # Determine Risk Level
        if final_score >= 85:
            risk_level = "CRITICAL"
        elif final_score >= 65:
            risk_level = "HIGH"
        elif final_score >= 35:
            risk_level = "MEDIUM"
        elif final_score >= 15:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        category = categories_detected[0] if categories_detected else ("Social Engineering" if final_score > 40 else "Informational Message")
        is_legitimate = (risk_level in ["SAFE", "LOW"])

        # Default recommended actions if empty
        if not recommended_actions:
            if is_legitimate:
                recommended_actions.append("This message exhibits standard characteristics of a legitimate notification.")
                recommended_actions.append("Remember the golden rule: Never share OTPs or passwords with anyone over the phone.")
            else:
                recommended_actions.append("Do not click any embedded links or call phone numbers mentioned in the message.")
                recommended_actions.append("Verify directly through the company's official mobile application or verified website.")
                recommended_actions.append("Block the sender and report the message to your cellular provider / spam filter.")

        # Summary generation
        if risk_level in ["CRITICAL", "HIGH"]:
            summary = f"Dangerous {category} alert. This message displays aggressive social engineering, requesting sensitive actions under false pretenses or manufactured urgency. Interacting with it carries a severe risk of financial loss or identity theft."
        elif risk_level == "MEDIUM":
            summary = f"Caution recommended. This message contains suspicious elements ({category}) such as unverified links or vague requests, but lacks conclusive high-severity extortion indicators."
        else:
            summary = "This message appears to be a legitimate communication following standard security notifications with no immediate threat indicators."

        # Confidence calculation
        confidence = 0.95 if (len(red_flags) >= 2 or is_legitimate) else 0.84

        return {
            "riskLevel": risk_level,
            "riskScore": final_score,
            "category": category,
            "summary": summary,
            "redFlags": red_flags,
            "whyFlagged": why_flagged,
            "recommendedActions": list(dict.fromkeys(recommended_actions)), # Deduplicate
            "detectedPhrases": detected_phrases,
            "extractedEntities": {
                "urls": urls,
                "phoneNumbers": list(set(phone_matches)),
                "emails": list(set(email_matches)),
                "monetaryAmounts": list(set(money_matches)),
                "impersonatedEntity": impersonated_brand,
                "suspiciousDomains": domain_reports
            },
            "confidence": confidence,
            "isLegitimate": is_legitimate,
            "engineUsed": "ScamShield Heuristic Defense Engine",
            "analyzedAt": now_iso
        }

threat_engine = ThreatIntelligenceEngine()
