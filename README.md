# 🛡 PhishTriage

A self-hosted phishing URL triage tool powered by **URLScan.io**, **VirusTotal**, and **Claude AI**.  
Built for security analysts who need fast, automated verdicts on suspicious URLs — with full enrichment and a clean browser-based UI.

---

## Features

- **Single & Bulk URL Submission** — Submit one URL or paste a list for batch scanning via URLScan.io
- **Live Queue & Results Database** — Track pending scans and browse completed verdicts in real time
- **VirusTotal Enrichment** — Cross-reference domain, IP, and URL reputation from 70+ AV engines
- **AI-Powered URL Sanitization** — Uses Claude to strip tracking/PII parameters before submission, protecting analyst privacy
- **URLScan Search** — Query historical URLScan.io results and import them into your local database
- **Verdict Scoring** — Automatic `malicious / suspicious / low / safe` classification using combined URLScan + VT signals

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 (vanilla, no build step) |
| Backend | FastAPI + Uvicorn |
| Database | SQLite via SQLAlchemy |
| HTTP Client | HTTPX (async) |
| AI Layer | Anthropic Claude (URL sanitization) |
| APIs | URLScan.io · VirusTotal v3 |

---

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/WGUhchenh/phish-triage.git
cd phish-triage
```

### 2. Set up environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your API keys (see [Environment Variables](#environment-variables) below).

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
uvicorn main:app --reload
```

Then open your browser at `http://localhost:8000`.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `URLSCAN_API_KEY` | ✅ Yes | Your URLScan.io API key — [get one here](https://urlscan.io/user/signup) |
| `VT_API_KEY` | ⚠️ Optional | VirusTotal API key — enables VT enrichment tab. [Get one here](https://www.virustotal.com/gui/join-us) |
| `ANTHROPIC_API_KEY` | ⚠️ Optional | Enables AI-assisted URL parameter sanitization. Falls back to heuristic-only mode if not set. |

> ⚠️ **Never commit your `.env` file.** It is listed in `.gitignore` by default.

---

## Project Structure

```
phish-triage/
├── main.py          # FastAPI backend — API routes, DB models, URLScan/VT/Claude logic
├── index.html       # React frontend (single file, no build step required)
├── requirements.txt # Python dependencies
├── .env.example     # Environment variable template
├── .gitignore
└── scans.db         # SQLite database (auto-created on first run, gitignored)
```

---

## Security Notes

- URLs are sanitized before submission to remove tracking parameters and encoded PII
- The app is intended for **local or internal use only** — it is not hardened for public deployment
- API keys are loaded from environment variables and never exposed to the frontend

---

## Roadmap / Future Improvements

- [ ] Export scan results to CSV / JSON
- [ ] Email alert on high-confidence malicious verdict
- [ ] Docker / `docker-compose` support for easy deployment
- [ ] Role-based access control for team use
- [ ] Webhook support for SIEM/SOAR integration

---

## License

MIT License — see [LICENSE](LICENSE) for details.
