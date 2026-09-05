# Blue Team Log Analyzer + Threat Intel Enrichment

A CLI tool that parses SSH auth logs, detects brute-force login attempts, enriches
flagged IPs with live threat intelligence from AbuseIPDB, and outputs a colored
terminal report plus a CSV file.

## Project structure

```
bluepy_project/
├── analyzer/
│   ├── __init__.py
│   ├── models.py         # LogEntry data class
│   ├── log_parser.py     # File I/O + regex parsing
│   ├── detection.py      # Grouping + brute-force detection logic
│   ├── cache.py          # Local JSON cache for API results
│   ├── threat_intel.py   # AbuseIPDB API integration
│   ├── reporting.py      # CSV export + rich colored terminal output
│   └── cli.py            # argparse + main() orchestration
├── run.py                # Entry point
├── sample_logs/
│   └── auth.log          # Sample SSH auth log for testing
├── requirements.txt
├── .env.example           # Template for your API key
├── .gitignore
└── README.md
```

## Setup

1. Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

3. Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/) and create a `.env`
   file in the project root (copy `.env.example` and fill in your real key):
   ```
   ABUSEIPDB_KEY=your_real_key_here
   ```
   `.env` is already listed in `.gitignore` — it will never be committed.

## Usage

```powershell
python run.py --file sample_logs/auth.log --threshold 3
```

**Flags:**
- `--file` (required) — path to the log file to analyze
- `--threshold` — number of failed attempts within a 10-minute window to flag as
  brute-force (default: 5)
- `--output` — path to write the CSV report (default: `report.csv`)

## Web UI

Launch the visual dashboard with:

```powershell
python web_app.py
```

Then open `http://127.0.0.1:5000`. The dashboard starts with the bundled sample
log and accepts uploaded `.log` or `.txt` files. Set `ABUSEIPDB_KEY` in `.env`
to enable live enrichment; without it, local detection still works.

## What it does

1. **Parses** the log file with regex, extracting IP, timestamp, username, and status
2. **Groups** failed login attempts by source IP
3. **Detects** brute-force patterns (N+ failures within a 10-minute window)
4. **Enriches** flagged IPs via the AbuseIPDB API — checking a local cache first so
   repeated runs don't burn your API rate limit
5. **Reports** results as a color-coded terminal table (green/yellow/red by severity)
   and a CSV file

## Notes

- `cache.json` and `report.csv` are generated at runtime and are git-ignored.
- Regenerate your AbuseIPDB key if it's ever been exposed (e.g. pasted in a screenshot
  or shared publicly) — treat it like any other secret.
