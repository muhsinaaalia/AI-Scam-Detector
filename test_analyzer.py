import asyncio
import sys

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from models import AnalysisRequest
from analyzer import analyze_message
from sample_cases import SAMPLE_CASES
from threat_engine import threat_engine

async def run_tests():
    print("==================================================")
    print("   SCAMSHIELD TEST SUITE: FORENSIC VERIFICATION   ")
    print("==================================================")
    
    # 1. Test Threat Engine on all sample cases
    for case in SAMPLE_CASES:
        req = AnalysisRequest(
            text=case["text"],
            sender=case.get("sender"),
            channel=case.get("channel", "Unknown")
        )
        res = await analyze_message(req)
        score = res["riskScore"]
        level = res["riskLevel"]
        cat = res["category"]
        red_flags_cnt = len(res.get("redFlags", []))
        why_cnt = len(res.get("whyFlagged", []))
        
        print(f"\n[Case: {case['title']}]")
        print(f"  Channel: {case.get('channel')} | Sender: {case.get('sender')}")
        print(f"  Result Risk Level : {level} (Score: {score}/100)")
        print(f"  Category          : {cat}")
        print(f"  Red Flags Count   : {red_flags_cnt}")
        print(f"  Why Flagged Items : {why_cnt}")
        print(f"  Engine Used       : {res.get('engineUsed')}")
        print(f"  Summary           : {res.get('summary')[:90]}...")
        
        # Assertions
        if case["expectedRisk"] in ["CRITICAL", "HIGH"]:
            assert level in ["CRITICAL", "HIGH"], f"Expected HIGH/CRITICAL for {case['id']}, got {level}"
            assert score >= 60, f"Expected score >= 60 for {case['id']}, got {score}"
        elif case["expectedRisk"] == "SAFE":
            assert level in ["SAFE", "LOW"], f"Expected SAFE/LOW for {case['id']}, got {level}"
            assert score <= 30, f"Expected score <= 30 for {case['id']}, got {score}"
            
    print("\n--------------------------------------------------")
    print("  All automated attack vector test cases PASSED!  ")
    print("--------------------------------------------------")

if __name__ == "__main__":
    asyncio.run(run_tests())
