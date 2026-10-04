from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class AnalysisRequest(BaseModel):
    text: str = Field(..., description="Suspicious message or content to analyze")
    sender: Optional[str] = Field(None, description="Optional sender identifier, phone number, or header")
    channel: Optional[str] = Field("Unknown", description="Communication channel e.g. SMS, WhatsApp, Email, Telegram, Job, Social")
    apiKey: Optional[str] = Field(None, description="Optional user-provided Gemini API key for live analysis")

class RedFlagItem(BaseModel):
    title: str = Field(..., description="Short red flag title")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, or LOW")
    description: str = Field(..., description="Why this indicates a scam or security threat")
    quote: Optional[str] = Field(None, description="Exact phrase or excerpt detected in text")

class WhyFlaggedFactor(BaseModel):
    factor: str = Field(..., description="Name of social engineering or technical threat factor")
    explanation: str = Field(..., description="Plain-language forensic explanation")
    detectedQuote: Optional[str] = Field(None, description="Specific excerpt from message demonstrating this factor")

class DetectedPhrase(BaseModel):
    phrase: str = Field(..., description="Exact substring matched")
    reason: str = Field(..., description="Explanation of risk in this phrase")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, or LOW")

class ExtractedEntities(BaseModel):
    urls: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    monetaryAmounts: List[str] = Field(default_factory=list)
    impersonatedEntity: Optional[str] = None
    suspiciousDomains: List[Dict[str, Any]] = Field(default_factory=list)

class AnalysisResponse(BaseModel):
    riskLevel: str = Field(..., description="SAFE, LOW, MEDIUM, HIGH, or CRITICAL")
    riskScore: int = Field(..., ge=0, le=100, description="Risk score from 0 (completely safe) to 100 (maximum risk)")
    category: str = Field(..., description="Scam taxonomy category")
    summary: str = Field(..., description="Concise forensic summary for non-technical users")
    redFlags: List[RedFlagItem] = Field(default_factory=list)
    whyFlagged: List[WhyFlaggedFactor] = Field(default_factory=list)
    recommendedActions: List[str] = Field(default_factory=list)
    detectedPhrases: List[DetectedPhrase] = Field(default_factory=list)
    extractedEntities: ExtractedEntities = Field(default_factory=ExtractedEntities)
    confidence: float = Field(..., ge=0.0, le=1.0)
    isLegitimate: bool = Field(...)
    engineUsed: str = Field(...)
    analyzedAt: str = Field(...)
