from typing import List, Dict, Any

SAMPLE_CASES: List[Dict[str, Any]] = [
    {
        "id": "bank_kyc",
        "title": "Bank KYC Suspension",
        "tag": "Bank Scam",
        "icon": "building-2",
        "expectedRisk": "HIGH",
        "sender": "HDFC-NOTICE",
        "channel": "SMS",
        "text": "URGENT: Dear Customer, Your HDFC Bank NetBanking and debit card have been suspended due to incomplete KYC verification. Please click http://hdfc-kyc-update.xyz/login immediately to update your PAN and Aadhaar within 24 hours, otherwise your account will be permanently deactivated."
    },
    {
        "id": "upi_refund",
        "title": "UPI ₹24,999 Refund Trap",
        "tag": "UPI / Payment Scam",
        "icon": "zap",
        "expectedRisk": "CRITICAL",
        "sender": "+91 9821098210",
        "channel": "WhatsApp",
        "text": "Dear customer, you have received an instant refund of Rs. 24,999 from PhonePe Merchant Services. To receive the money directly into your bank account, scan the attached QR code and enter your 4-digit UPI PIN now. Valid for 15 minutes only."
    },
    {
        "id": "telegram_job",
        "title": "Telegram YouTube Task Job",
        "tag": "Job Scam",
        "icon": "briefcase",
        "expectedRisk": "HIGH",
        "sender": "Natasha HR",
        "channel": "Telegram",
        "text": "Hello! I am Natasha from Global Media HR. We have part-time work from home opportunities. Just like 3 YouTube videos and get Rs. 500 per task. You can earn Rs. 3,000 to Rs. 8,000 daily with instant payout to UPI. Contact HR Manager on Telegram: @GlobalMedia_HR88 to start immediately!"
    },
    {
        "id": "fedex_arrest",
        "title": "FedEx Police Digital Arrest",
        "tag": "Digital Arrest Extortion",
        "icon": "shield-alert",
        "expectedRisk": "CRITICAL",
        "sender": "+91 8812345678",
        "channel": "WhatsApp Call / SMS",
        "text": "IMPORTANT NOTICE from FedEx Express: Parcel tracking #FX-982181 registered under your Aadhaar card has been seized by Mumbai Customs. The package contains 5 fake passports and 150 grams of prohibited narcotics. An arrest warrant has been issued by Cyber Crime Branch. Connect on Skype/WhatsApp immediately with Inspector Sharma at +91-9876543210 to avoid police arrest."
    },
    {
        "id": "prize_lottery",
        "title": "KBC WhatsApp ₹25 Lakh Lottery",
        "tag": "Prize / Lottery Scam",
        "icon": "trophy",
        "expectedRisk": "HIGH",
        "sender": "+92 300 1234567",
        "channel": "WhatsApp",
        "text": "CONGRATULATIONS! Your mobile number has won 1st Prize of Rs. 25,00,000 in Kaun Banega Crorepati (KBC) WhatsApp Lucky Draw 2026. To claim your prize money, send Rs. 4,500 for government tax clearance certificate to UPI ID: kbcluckydraw@okaxis within 2 hours."
    },
    {
        "id": "insta_phishing",
        "title": "Instagram Account Breach Threat",
        "tag": "Phishing",
        "icon": "key-round",
        "expectedRisk": "HIGH",
        "sender": "security@mail-instagram-alerts.top",
        "channel": "Email",
        "text": "Instagram Security Team: We detected an unauthorized login attempt to your account from Moscow, Russia. If this was not you, confirm your credentials within 12 hours at https://insta-verify-support.online/secure-login to avoid permanent account deletion."
    },
    {
        "id": "legit_bank_otp",
        "title": "Legitimate Bank OTP Notice",
        "tag": "Legitimate Alert",
        "icon": "shield-check",
        "expectedRisk": "SAFE",
        "sender": "VM-HDFCBK",
        "channel": "SMS",
        "text": "Your one-time password (OTP) for transaction of Rs. 450.00 at Zomato is 782914. Valid for 10 mins. NEVER share your OTP or PIN with anyone, even if they claim to be from HDFC Bank. Bank staff never asks for OTP."
    },
    {
        "id": "legit_amazon_delivery",
        "title": "Legitimate Amazon Package Dispatch",
        "tag": "Legitimate Delivery",
        "icon": "package",
        "expectedRisk": "SAFE",
        "sender": "AM-AMAZON",
        "channel": "SMS",
        "text": "Hi Rahul, your order #8921-391 from Amazon has been dispatched with delivery agent Suresh (+91 9123456780). Expected delivery by 8:00 PM today. Track your order on the official Amazon app. No payment is required for this prepaid package."
    }
]
