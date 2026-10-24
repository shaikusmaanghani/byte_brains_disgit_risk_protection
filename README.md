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
Copy-Item .env.example .env
```

### 3. Run Automated Detection Engine Tests
```bash
npm test
```

### 4. Start Full-Stack SOC Server
```bash
npm run dev
```
Open **http://localhost:3000** in your browser.

---

## 🧑‍💻 Demo User Accounts

These demo accounts are for local demonstration only. Passwords are scrypt-hashed server-side; never reuse a real password.

| Role | Email | Password |
|---|---|---|
| Analyst 1 | `analyst1@sentinelshield.demo` | `AnalystDemo2026!` |
| Analyst 2 | `analyst2@sentinelshield.demo` | `Analyst2Demo2026!` |
| Admin | `admin@sentinelshield.demo` | `AdminDemo2026!` |

---

## 🎬 Round 2 — 3-minute SOC demonstration guide

1. Log in as Analyst 1 with the demo credentials above.
2. Open **Threat Findings** and select the highest-scoring detection; inspect its priority score and alert bell.
3. Review the side-by-side comparison and each evidence signal's points and plain-language explanation.
4. Enter an analyst reason and select **Confirm Threat**; verify the actor and timestamp in history.
5. Generate the confirmed-only takedown draft, edit it, copy it, export `.md`/`.txt`, or print to PDF.
6. Run a scan. A newly high-risk detection fires one alert; re-scanning does not duplicate that alert unless severity escalates.
7. Mark **Acme Financial Fan Club** as False Positive with a reason; it leaves the default priority queue.
8. Ask the offline assistant “What are the top 5 risks?”, “Why is #1 scored?”, or “What did Analyst One do on #1?”

## Explainable scoring

Scoring weights and severity thresholds are defined in `src/services/scoringConfig.ts`. Signals are deterministic, additive, capped at 100, and persisted with each detection.

| Signal | Maximum points | Details |
|---|---:|---|
| Name / handle similarity | 25 | Damerau-Levenshtein plus Jaro-Winkler, confusable normalization, modifier removal |
| Exact official app name + unknown publisher | +20 | Explicit exact-clone indicator |
| Publisher mismatch | 20 | Publisher not in the registered publisher list |
| Developer mismatch | 15 | Applied separately when publisher and developer differ |
| Description overlap | 15 | Token Jaccard and registered brand terms |
| Logo dHash resemblance | 10 | Hamming distance between supplied 64-bit hexadecimal dHashes |
| Package mismatch | 5 | Non-official app package identifier |
| Non-official domain | 5 | Candidate link is not in the official-domain allowlist |
| Suspicious language / permissions | 5 | Login, urgent verification, giveaway, rewards, sensitive permissions |
| Homoglyph substitution | 15 | Confusable Unicode and common character substitutions |
| Recent creation | 5 | Candidate creation date within 14 days |

Severity: Critical ≥85, High ≥75, Medium ≥50, Low ≥20, Informational <20. `HIGH_THRESHOLD` defaults to 75. Logo similarity is skipped and explained if the ingestion source has not supplied a 64-bit logo hash. Scoring never claims a pHash result from a URL alone.

`npm run seed` adds 18 clearly labelled simulated detections through the Round 1 TypeScript engine. The seed includes a near-copy app, social lookalikes, a harmless fan page, a homoglyph domain string, and copied description under a different publisher. The allowlisted official app is deliberately excluded. Re-running is idempotent by platform and identifier. Seed records are demonstration data, not live intelligence.

### Screenshot / GIF checklist

- [ ] Demo login and labelled credentials
- [ ] Priority queue filters, scores, severity colors, and summary cards
- [ ] Detection detail comparison and “why this score” evidence
- [ ] Status transition and timestamped history
- [ ] Alert bell before/after a repeated scan
- [ ] Editable takedown draft and exported report
- [ ] Offline assistant response citing detection IDs

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
