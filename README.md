# SentinelShield — Digital Risk Protection (Social & App Monitoring)

[![Security Operations Center](https://img.shields.io/badge/SOC-DRP%20Platform-06b6d4)](https://github.com)
[![Engine](https://img.shields.io/badge/Detection%20Engine-Explainable%20v3.8-10b981)](https://github.com)
[![Tests](https://img.shields.io/badge/Tests-8%20Passed-emerald)](https://github.com)

SentinelShield is an enterprise Digital Risk Protection (DRP) and Brand Impersonation Defense platform designed for Security Operations Centers (SOC). It continuously monitors mobile application stores (Google Play, Apple App Store) and social networks (X/Twitter, LinkedIn, Instagram, Facebook, YouTube) for fraudulent brand impersonation, spoofing, and rogue applications.

---

## 🏛️ Architecture Overview

```
            ┌───────────────────────┐
            │       FRONTEND        │
            │ React + TypeScript    │
            │ Dashboard / SOC UI    │
            └───────────┬───────────┘
                        │ REST API (Port 3000)
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

---

## 🔍 Threat Detection Engine Highlights

The engine strictly evaluates multi-vector evidence without naively flagging based on fuzzy-matching alone:

1. **Official Asset Exclusion Gate**:
   - Compares candidate `packageId`, `platform`, `publisher`, and `developer`.
   - Matches against registered credentials immediately bypass threats (`Risk Score: 0`, `Status: Official Asset`).
2. **Publisher Mismatch Analysis**:
   - Identifies applications cloning brand names under unauthorized developer accounts.
   - Example: *Acme Mobile Banking* by `Rogue Apps LLC` generates a **+20 pt Publisher Mismatch** + **+15 pt Developer Mismatch**.
3. **Unicode & Homoglyph Normalization**:
   - Replaces confusable Latin/Cyrillic characters (e.g. Cyrillic `а` \u0430, `е` \u0435, `о` \u043e) and uppercase `I` spoofing lowercase `l` (e.g. `@acme_financiaI`).
4. **Damerau-Levenshtein & Transposition Detection**:
   - Catches look-alike typosquatting (e.g. `Acme Finanical Banking`).
5. **Explainable Scoring Weights (Max: 100 Pts)**:
   - Name Similarity: 0–25 pts
   - Publisher Mismatch: 0–20 pts
   - Developer Mismatch: 0–15 pts
   - Description & Phishing Mimicry: 0–15 pts
   - Logo / Icon Signature: 0–10 pts
   - Package ID Mismatch: 0–5 pts
   - Destination Domain Mismatch: 0–5 pts
   - Sensitive Permissions / Phishing Lures: 0–5 pts

---

## 🚀 Quickstart & Installation

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env
```

### 3. Run Automated Detection Engine Tests
```bash
npm test
# or: npx tsx tests/detection.test.ts
```

### 4. Start Full-Stack SOC Server
```bash
npm run dev
# Starts full-stack Express REST API + Vite middlewares on port 3000
```
Open **http://localhost:3000** in your browser.

---

## 🧑‍💻 Demo User Accounts

| Role | Name | Email | Permissions |
|---|---|---|---|
| **Admin** | Marcus Vance | `admin@sentinelshield.io` | Full System & Policy Control |
| **Analyst** | Sarah Chen | `sarah.chen@sentinelshield.io` | Investigations, Notes & Status |
| **Viewer** | David Mercer | `viewer@sentinelshield.io` | Read-only Auditing |

*(You can switch between roles in one click from the header avatar dropdown.)*

---

## 🎬 11-Step SOC Demonstration Guide

1. **Brand Profile**: View registered brand **Acme Financial** and official production apps.
2. **Official App Whitelist**: Examine *Acme Mobile Banking* (Package: `com.acme.mobilebanking`, Publisher: `Acme Financial Technologies LLC`).
3. **Run Monitoring Scan**: Click **"Run Monitoring Scan"** in the header to dispatch the simulated surveillance crawler.
4. **Discovered Threat**: The engine flags *Acme Mobile Banking* by `Rogue Apps LLC`.
5. **Evaluation**:
   - **Risk Score: 92/100 (CRITICAL)**
   - **Signals**: Name Similarity (25), Publisher Mismatch (20), Developer Mismatch (15), Description Mimicry (15), Package Mismatch (5), Domain Mismatch (5).
6. **Threat Detail**: Open the finding to view the **Side-by-Side Diff** (Candidate vs Official).
7. **Impersonation Radar**: Inspect the 8-axis geometric radar showing why the app was flagged.
8. **Threat Relationship Graph**: Navigate to **Threat Graph** to visualize the link between Acme Financial, the unauthorized publisher, and the rogue APK.
9. **Analyst Workflow**: Transition status from `New` to `Confirmed Threat`, assign analyst `Sarah Chen`, and record an investigation note.
10. **Brand Twin Scanner**: Test manual evaluation by loading presets (`Rogue Banking App`, `Homoglyph Latin I Spoof`, `Official Asset Exclusion`).
11. **Generate Report**: Go to **Executive Reports** and export as **CSV**, **JSON**, or print a styled **PDF report**.

---

## 📁 Repository Structure

```
├── backend/            # FastAPI Python backend (engine, schemas, routers)
├── database/           # PostgreSQL & SQLite relational SQL schema
├── docker/             # Dockerfile and docker-compose.yml
├── docs/               # Architecture, API specifications, and detection guides
├── server/             # Express REST API, persistence manager, and seed data
├── src/
│   ├── assets/         # High-resolution SOC emblems and analyst visuals
│   ├── components/     # Header, Sidebar, RadarChart, ThreatGraph, Modals
│   ├── pages/          # Dashboard, Findings, Twin Scanner, Monitoring, Analytics
│   ├── services/       # DetectionEngine, API client
│   └── types/          # Domain models and TypeScript contracts
├── tests/              # Automated detection engine test suite
└── server.ts           # Full-stack server mounting REST API & Vite on port 3000
```
