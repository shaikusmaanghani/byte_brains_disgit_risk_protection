# SentinelShield Architectural Specification

## System Overview
SentinelShield is an enterprise Digital Risk Protection (DRP) and Brand Impersonation Defense platform designed for Security Operations Centers (SOC). It continuously monitors mobile application stores (Google Play, Apple App Store) and social networks (X, LinkedIn, Instagram, Facebook, YouTube) for fraudulent brand impersonation, spoofing, and rogue applications.

```
            ┌───────────────────────┐
            │       FRONTEND        │
            │ React + TypeScript    │
            │ Dashboard / SOC UI    │
            └───────────┬───────────┘
                        │ REST API (Vite proxy / Express / FastAPI)
                        ▼
            ┌───────────────────────┐
            │   FASTAPI / EXPRESS   │
            │ Authentication (JWT)  │
            │ API / Validation      │
            └───────────┬───────────┘
                        │
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
   ┌───────────┐ ┌────────────┐ ┌──────────────┐
   │ Detection │ │ Monitoring │ │  Analytics   │
   │ Engine    │ │  Service   │ │   Service    │
   └─────┬─────┘ └─────┬──────┘ └──────┬───────┘
         │             │               │
         └─────────────┼───────────────┘
                       ▼
                ┌─────────────┐
                │ PostgreSQL  │
                │ / SQLite DB │
                └─────────────┘
```

## Detection Pipeline
1. **Unicode & Homoglyph Normalization**: Transforms confusable characters (Cyrillic look-alikes `а`, `е`, `о`, `р`, `с`, `у`, `х`, Greek characters, and Latin uppercase `I` disguised as lowercase `l`) to base Latin ASCII.
2. **Official Asset Exclusion Gate**: Candidate items matching registered official credentials (`packageId`, `platform`, `publisher`, or exact official handle) are granted `Risk Score: 0` (Official Asset) and excluded from threat alerts.
3. **Multi-Signal Feature Extraction**:
   - Name & Handle similarity via Damerau-Levenshtein and token containment.
   - Publisher & Developer mismatch check against authorized whitelist.
   - Package ID differentiation.
   - Description mimicry and financial/banking lure detection.
   - Domain affiliation verification against corporate DNS records.
   - Pluggable perceptual logo similarity.
4. **Explainable Scoring Engine**: Computes structured, explainable evidence weights (0–100) and maps them to severity tiers (`Critical`, `High`, `Medium`, `Low`, `Informational`).
5. **Analyst Workflow & Escalation**: Supports status progression (`New` -> `Investigating` -> `Confirmed Threat` -> `Resolved`/`Dismissed`), analyst notes, and PDF/CSV compliance exports.
