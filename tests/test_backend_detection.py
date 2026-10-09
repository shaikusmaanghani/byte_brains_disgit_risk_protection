"""
Pytest suite for SentinelShield Python Detection Engine
"""

import pytest
from backend.detection.engine import (
    analyze_app_threat,
    detect_and_normalize_homoglyphs,
    string_similarity,
)

SAMPLE_BRAND = {
    "name": "Acme Financial",
    "knownPublishers": ["Acme Financial Technologies LLC"],
    "knownDevelopers": ["Acme Financial Technologies Dev Team"],
    "officialApps": [
        {
            "appName": "Acme Mobile Banking",
            "packageId": "com.acme.mobilebanking",
            "platform": "google_play",
            "developer": "Acme Financial Technologies Dev Team",
            "publisher": "Acme Financial Technologies LLC",
        }
    ]
}

def test_official_app_exclusion():
    candidate = {
        "appName": "Acme Mobile Banking",
        "developer": "Acme Financial Technologies Dev Team",
        "publisher": "Acme Financial Technologies LLC",
        "packageId": "com.acme.mobilebanking",
        "platform": "google_play",
    }
    result = analyze_app_threat(candidate, SAMPLE_BRAND)
    assert result["is_official_asset"] is True
    assert result["risk_score"] == 0
    assert result["risk_level"] == "informational"

def test_publisher_mismatch_critical():
    candidate = {
        "appName": "Acme Mobile Banking",
        "developer": "Rogue Apps LLC",
        "publisher": "Rogue Apps LLC",
        "packageId": "com.fake.acme.bank",
        "platform": "google_play",
        "description": "Official Acme secure banking application.",
    }
    result = analyze_app_threat(candidate, SAMPLE_BRAND)
    assert result["is_official_asset"] is False
    assert result["risk_score"] >= 80
    assert result["risk_level"] == "critical"
    
    pub_signals = [s for s in result["signals"] if s["type"] == "publisher_mismatch"]
    assert len(pub_signals) > 0
    assert pub_signals[0]["score"] == 20

def test_homoglyph_detection():
    norm, has_homo, chars = detect_and_normalize_homoglyphs("AcmeFinanciaI")
    assert has_homo is True
    assert norm == "AcmeFinancial"
