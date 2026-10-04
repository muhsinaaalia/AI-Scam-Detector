import os
import logging
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from models import AnalysisRequest, AnalysisResponse
from analyzer import analyze_message
from threat_engine import threat_engine
from sample_cases import SAMPLE_CASES

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("scamshield.server")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="ScamShield API",
    description="AI-Powered Scam & Phishing Risk Analyzer",
    version="1.0.0"
)

# Enable CORS for development and demo flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UrlCheckRequest(BaseModel):
    url: str

@app.get("/api/status")
async def get_status():
    has_env_key = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    return {
        "status": "online",
        "product": "ScamShield",
        "tagline": "Think before you click.",
        "version": "1.0.0",
        "geminiConfigured": has_env_key,
        "activeEngine": "Gemini 2.5 Flash + Heuristic Defense" if has_env_key else "Heuristic Cyber Defense Engine (Local)",
        "message": "AI Scam & Phishing Risk Analyzer is ready."
    }

@app.get("/api/sample-cases")
async def get_sample_cases():
    return {
        "count": len(SAMPLE_CASES),
        "cases": SAMPLE_CASES
    }

@app.post("/api/analyze")
async def analyze_endpoint(request: AnalysisRequest):
    if not request.text or len(request.text.strip()) == 0:
        raise HTTPException(status_code=400, detail="Message text cannot be empty.")
    
    try:
        result = await analyze_message(request)
        return result
    except Exception as e:
        logger.error(f"Error during analysis: {e}", exc_info=True)
        # Resilient fallback so the user always gets a meaningful analysis
        fallback = threat_engine.analyze(request.text, request.sender, request.channel)
        return fallback

@app.post("/api/check-url")
async def check_url_endpoint(req: UrlCheckRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return threat_engine.analyze_domain(req.url)

# Mount static files
if not STATIC_DIR.exists():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"message": "ScamShield API running. Frontend index.html not yet created."})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
