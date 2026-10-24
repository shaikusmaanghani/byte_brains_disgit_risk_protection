"""
SentinelShield Pydantic Schemas
Production-grade request/response schemas for brand protection & threat analysis.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class OfficialAppSchema(BaseModel):
    id: str
    appName: str
    packageId: str
    platform: str
    developer: str
    publisher: str
    storeUrl: str
    version: str
    category: str
    iconUrl: Optional[str] = None
    officialDomain: Optional[str] = None
    logoHash: Optional[str] = None

class OfficialSocialAccountSchema(BaseModel):
    id: str
    platform: str
    handle: str
    profileName: str
    profileUrl: str
    verified: bool
    avatarUrl: Optional[str] = None
    avatarHash: Optional[str] = None

class BrandProfileSchema(BaseModel):
    id: str
    name: str
    logoUrl: str
    logoHash: Optional[str] = None
    aliases: List[str] = []
    officialDomains: List[str] = []
    brandKeywords: List[str] = []
    productNames: List[str] = []
    supportEmailDomains: List[str] = []
    officialWebsite: str
    companyDescription: str
    knownPublishers: List[str] = []
    knownDevelopers: List[str] = []
    officialApps: List[OfficialAppSchema] = []
    officialSocialAccounts: List[OfficialSocialAccountSchema] = []

class AppCandidateInput(BaseModel):
    appName: str
    developer: str
    publisher: str
    packageId: str
    description: str
    category: Optional[str] = None
    platform: str = "google_play"
    storeUrl: Optional[str] = None
    iconUrl: Optional[str] = None
    version: Optional[str] = None
    permissions: Optional[List[str]] = []
    website: Optional[str] = None
    createdAt: Optional[str] = None
    logoHash: Optional[str] = None

class SocialCandidateInput(BaseModel):
    platform: str
    profileName: str
    username: str
    biography: str
    profileUrl: Optional[str] = None
    followerCount: Optional[int] = 0
    verified: Optional[bool] = False
    avatarUrl: Optional[str] = None
    links: Optional[List[str]] = []
    keywords: Optional[List[str]] = []
    createdAt: Optional[str] = None
    avatarHash: Optional[str] = None

class DetectionSignalSchema(BaseModel):
    type: str
    score: int
    weight: int
    explanation: str
    evidenceSnippet: Optional[str] = None
    highlightDetails: Optional[Dict[str, Any]] = None

class AnalysisResultSchema(BaseModel):
    risk_score: int
    risk_level: str
    classification: str
    confidence: float
    is_official_asset: bool
    signals: List[DetectionSignalSchema]
    radar_breakdown: Dict[str, int]
    recommended_action: str
    summary_explanation: str
