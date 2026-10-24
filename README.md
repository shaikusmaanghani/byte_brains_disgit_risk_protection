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
            │       EXPRESS        │
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
                │  MongoDB    │
                │  (Mongoose) │
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
Set `MONGODB_URI` in `.env` to a reachable MongoDB instance before running the app or seed. The server fails at startup with a clear error if it is missing; it never falls back to the JSON file.

### 3. Run Automated Detection Engine Tests
```bash
npm test
```

### 4. Seed MongoDB with demo data
```bash
npm run seed
```
The seed imports 24 demo detections, the official-asset allowlist, alerts, and demo users with stored scrypt password hashes. Re-running is idempotent. To intentionally clear the SentinelShield collections before seeding, run `npm run seed -- --reset`.

For a one-time import of an existing `data/sentinel_db.json`, run:
```bash
npm run import:json
```

### 5. Start Full-Stack SOC Server
```bash
npm run dev
```
Open **http://localhost:3000** in your browser.

Detection records, embedded evidence and history, alerts, users, and drafted reports are stored in MongoDB. Brand profile, monitoring sources, watchlists, and scan counters are persisted in the MongoDB app-state collection.

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
| Logo resemblance | 10 | Fetched-image pHash + dHash Hamming distances and dominant-color histogram; unavailable images are skipped |
| Package mismatch | 5 | Non-official app package identifier |
| Non-official domain | 5 | Candidate link is not in the official-domain allowlist |
| Suspicious language / permissions | 5 | Login, urgent verification, giveaway, rewards, sensitive permissions |
| Homoglyph substitution | 15 | Confusable Unicode and common character substitutions |
| Recent creation | 5 | Candidate creation date within 14 days |

Severity: Critical ≥85, High ≥75, Medium ≥50, Low ≥20, Informational <20. `HIGH_THRESHOLD` defaults to 75. `LOGO_MATCH_THRESHOLD` defaults to 80%. Candidate images are fetched with public-IP, HTTP(S)-only, redirect, content-type, five-second timeout, and 2 MB size guards. Official image hashes are cached in MongoDB. The score explanation records similarity, pHash and dHash distances, histogram similarity, and method. A missing or unsafe image is explicitly recorded as “Logo not available” and does not penalize the candidate.

`npm run seed` loads the 24 clearly labelled simulated detections from the existing Round 1 JSON dataset into MongoDB, including a near-copy app, social lookalikes, a harmless fan page, a homoglyph domain, and copied description under a different publisher. The official-asset allowlist is stored alongside the brand profile. Re-running is idempotent by detection ID. Seed records are demonstration data, not live intelligence.

## Live Brand Threat Radar

The dashboard reads its protected brand name, official domains, logo, and allowlist from MongoDB (currently the stored profile is **Acme Financial**). On dashboard open it requests a scan, then refreshes the MongoDB-backed radar summary every 15 seconds while the tab is visible. The authenticated `GET /api/radar/summary` response is produced by one MongoDB aggregation pipeline and cached for at most 10 seconds; False Positive, Closed, and allowlisted official assets are excluded. Counts distinguish suspected/unconfirmed records from analyst-confirmed records.

`POST /api/radar/scan` starts a bounded scan when the MongoDB lock is free and `SCAN_COOLDOWN_MINUTES` (default 10) has elapsed. Concurrent visits share the scan lock. Vercel Cron calls `GET /api/radar/scan` every 15 minutes and requires `CRON_SECRET` as a bearer token. Configure the secret in the deployment environment; do not commit its value.
The dashboard’s manual **Run Surface Scan** action and compatibility endpoint `POST /api/monitoring/run` use this same live scanner; they do not add synthetic candidates. Demo seed records remain visibly labeled.

| Source | Radar behavior |
|---|---|
| Lookalike domains | Generates a bounded set of typo variants from stored official domains, checks public DNS, queries Certificate Transparency (`crt.sh`), then inspects live pages and their title, description, favicon, and Open Graph image. |
| Apple App Store | Uses the public iTunes Search API for the stored brand name and scores returned app metadata/icons. |
| Google Play | Explicitly reports `skipped`; no fabricated results are presented when a supported search connector is unavailable. |
| Social platforms | Existing seed/ingest rows are labeled **Demo data**. X/Meta/LinkedIn are connector placeholders and report `skipped` even when optional credentials (`X_BEARER_TOKEN`, `META_ACCESS_TOKEN`, `LINKEDIN_ACCESS_TOKEN`) are present; they are not claimed live integrations. |

Live domain and app-store results are stored through the existing platform+identifier upsert and scoring/alert flow. Official accounts/apps/domains are excluded before ingest and in summary aggregation. `LOGO_MATCH_THRESHOLD` controls the matching-logo count and badge. A logo is marked as matching only at or above that threshold; measured values remain visible in detection evidence and confirmed-only takedown drafts.

### 30-second radar demo

1. Open the dashboard and watch the scan indicator, source states, and live suspected/confirmed counts.
2. Open a top-five detection and compare its candidate logo with the official logo; inspect the measured score and pHash/dHash evidence.
3. Confirm a suspected record and observe the confirmed count update; mark another False Positive and observe the suspected count drop.
4. Ask the analyst chatbot: “How many fake profiles are there for Acme Financial Bank?” It responds with the stored brand’s suspected/confirmed split, logo-match count, latest scan time, and detection IDs.

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
├── database/           # Legacy relational schema reference
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
