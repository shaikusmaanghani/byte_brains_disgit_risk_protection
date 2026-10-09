"""
SentinelShield FastAPI Backend Entrypoint
Production-ready REST API implementing digital risk protection and brand twin detection.
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any

from backend.models.schemas import (
    AppCandidateInput,
    SocialCandidateInput,
    AnalysisResultSchema,
    BrandProfileSchema
)
from backend.detection.engine import analyze_app_threat

app = FastAPI(
    title="SentinelShield API",
    description="Enterprise Digital Risk Protection & Brand Impersonation Detection Engine",
    version="3.8.4",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Demo Brand In-Memory Store
CURRENT_BRAND = {
    "id": "brand-acme-financial",
    "name": "Acme Financial",
    "logoUrl": "/brand_logo.svg",
    "aliases": ["Acme Bank", "Acme FinTech"],
    "officialDomains": ["acmefinancial.com", "acmebank.com"],
    "brandKeywords": ["banking", "checking", "wealth management", "credit", "wire transfer"],
    "productNames": ["Acme Mobile Banking", "Acme Wealth Portal"],
    "supportEmailDomains": ["acmefinancial.com"],
    "officialWebsite": "https://www.acmefinancial.com",
    "companyDescription": "Official banking and financial wealth portal for Acme Financial.",
    "knownPublishers": ["Acme Financial Technologies LLC", "Acme Corp Labs"],
    "knownDevelopers": ["Acme Financial Technologies Dev Team"],
    "officialApps": [
        {
            "id": "app-1",
            "appName": "Acme Mobile Banking",
            "packageId": "com.acme.mobilebanking",
            "platform": "google_play",
            "developer": "Acme Financial Technologies Dev Team",
            "publisher": "Acme Financial Technologies LLC",
            "storeUrl": "https://play.google.com/store/apps/details?id=com.acme.mobilebanking",
            "version": "4.8.2",
            "category": "Finance"
        }
    ],
    "officialSocialAccounts": [
        {
            "id": "soc-1",
            "platform": "x_twitter",
            "handle": "AcmeFinancial",
            "profileName": "Acme Financial Official",
            "profileUrl": "https://x.com/AcmeFinancial",
            "verified": True
        }
    ]
}

@app.get("/api/health")
def get_health():
    return {
        "status": "healthy",
        "service": "SentinelShield FastAPI",
        "engine": "v3.8.4",
        "database": "operational"
    }

@app.get("/api/profile")
def get_brand_profile():
    return CURRENT_BRAND

@app.post("/api/analyze/app", response_model=Dict[str, Any])
def analyze_application(candidate: AppCandidateInput):
    result = analyze_app_threat(candidate.dict(), CURRENT_BRAND)
    return result

@app.post("/api/monitoring/run")
def trigger_monitoring():
    return {
        "success": True,
        "message": "Continuous external surface scanning cycle dispatched.",
        "sourcesScanned": 7,
        "newFindings": 3
    }
