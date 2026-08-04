# DLP Audit Log Analyzer

A production-quality Python script that reads Google Cloud / Google Workspace security audit logs, correlates related events into incidents, computes an explainable risk score for each incident, and exports a prioritized report.

Built as an implementation of the RFC: Data Loss Prevention for Colibrí, a fintech running on Google Workspace and GCP.

**RFC:** [R.F.C — Data Loss Prevention (Google Docs)](https://docs.google.com/document/d/1c8lxG3ljbUn2aL6Cp-s24CK7QlsfLAxCBssqafkyNKQ/edit?usp=sharing)

---

## Project Structure

```
dlp_challenge/
├── README.md
├── requirements.txt
│
├── data/
│   ├── mock_logs_json_cloud_audit.json
│   └── mock_logs_csv_cloud_audit.csv
│
├── src/
│   ├── models.py       — AuditEvent and Incident dataclasses (data contracts)
│   ├── parser.py       — JSON/CSV ingestion and normalization
│   ├── correlator.py   — Event grouping into incidents
│   ├── scorer.py       — Deterministic multi-signal risk scoring
│   ├── exporter.py     — CSV report generation
│   └── main.py         — Pipeline orchestration and CLI entry point
│
└── output/
    └── prioritized_incidents.csv   (generated on run)
```

---

## Requirements

- Python 3.10 or later
- No third-party dependencies — standard library only

---

## Installation

```bash
git clone <repository-url>
cd dlp_challenge
```

No `pip install` step required.

---

## Usage

```bash
# JSON input
python src/main.py data/mock_logs_json_cloud_audit.json

# CSV input
python src/main.py data/mock_logs_csv_cloud_audit.csv

# Custom output path
python src/main.py data/mock_logs_json_cloud_audit.json --output reports/incidents.csv

# Verbose (debug-level) logging
python src/main.py data/mock_logs_json_cloud_audit.json --verbose
```

The report is written to `output/prioritized_incidents.csv` by default.

---

## Pipeline Stages

```
Input file (.json or .csv)
        │
        ▼
   parser.py  ──►  list[AuditEvent]        (normalized, format-agnostic)
        │
        ▼
correlator.py  ──►  list[Incident]          (events grouped by pattern)
        │
        ▼
   scorer.py  ──►  list[Incident]           (scored, sorted, severity assigned)
        │
        ▼
  exporter.py  ──►  output/prioritized_incidents.csv
```

---

## How Correlation Works

Events are grouped into incidents using two rules. Each event belongs to exactly one incident.

### Rule 1 — Geographic campaign (48-hour window)

Events targeting the **same resource from the same country** within 48 hours are grouped together.

This pattern detects coordinated regional attacks or compromised geographic locations repeatedly accessing a sensitive resource (e.g., 15 events from China targeting `resource2` in a 48-hour window).

### Rule 2 — Destination campaign (48-hour window)

Events sharing the **same external destination** with a `public` or `external` sharing scope within 48 hours are grouped together.

This pattern detects repeated data exfiltration to the same external endpoint from multiple sources (e.g., multiple users sending data to `External Email` with public scope in a short window).

### Fallback

Any event not matched by either rule becomes a single-event incident on its own.

### Configuration

Time windows are named constants at the top of `src/correlator.py`:

```python
GEOGRAPHIC_WINDOW_HOURS: int = 48
DESTINATION_WINDOW_HOURS: int = 48
```

---

## How the Risk Score Works

Each incident receives a score between 0 and 100. The score is built incrementally by evaluating nine independent signals. Each signal that fires adds points and appends a human-readable reason to the incident.

| # | Signal | Max pts | What it captures |
|---|---|---|---|
| 1 | Contains PII | 20 | Data classified as Restricted per the RFC |
| 2 | Sharing scope (public / external / internal) | 25 / 15 / 5 | Exposure radius |
| 3 | Records affected (>1k / >100 / >10) | 25 / 10 / 5 | Data volume |
| 4 | Suspicious activity flag | 15 | Behavioral classifier signal |
| 5 | Successful suspicious action | 10 | Confirmed exfiltration vs failed attempt |
| 6 | Service risk (BigQuery / IAM / Storage) | 10 / 10 / 5 | Platform-level risk profile |
| 7 | Dangerous action (make_public / export / download) | 15 / 10 / 8 | Action severity |
| 8 | Weak authentication (password only) | 5 | No MFA or SSO |
| 9 | Correlation depth (5+ / 3+ / 2 events) | 15 / 10 / 5 | Campaign indicator |

The final score is capped at 100.

### Severity thresholds

| Severity | Score |
|---|---|
| Critical | ≥ 75 |
| High | ≥ 50 |
| Medium | ≥ 25 |
| Low | < 25 |

Thresholds are defined as a single dict in `src/scorer.py`:

```python
SEVERITY_THRESHOLDS: dict[str, int] = {
    "Critical": 75,
    "High":     50,
    "Medium":   25,
    "Low":       0,
}
```

### Example output row

```
incident_id  risk_score  severity  user_email              resource_name  service      events_correlated  reasons
INC-00001    100         Critical  user@example.com        resource2      BigQuery     7                  +20 Contains PII | +25 Data exposed publicly | +25 Large volume... | ...
```

---

## Output Format

`output/prioritized_incidents.csv` — one row per incident, sorted by `risk_score` descending.

| Column | Description |
|---|---|
| `incident_id` | Deterministic identifier (INC-00001, …) |
| `risk_score` | 0–100 |
| `severity` | Low / Medium / High / Critical |
| `user_email` | User from the primary (earliest) event |
| `resource_name` | Resource from the primary event |
| `service` | GCP/Workspace service from the primary event |
| `events_correlated` | Number of events grouped into this incident |
| `timestamp` | Timestamp of the primary event (ISO 8601) |
| `reasons` | Pipe-separated list of scoring reasons |

---

## Assumptions

- Both input files contain the same columns. The parser validates required fields and skips malformed records with a warning.
- `event_id` values are unique within each file. They are used to track which events have been assigned to an incident during correlation.
- The two provided datasets (JSON and CSV) are structurally identical but independently generated — they contain different records. This is consistent with synthetic challenge data.
- Timestamps are assumed to be UTC (format: `YYYY-MM-DDTHH:MM:SSZ`).
- The scoring model is intentionally conservative at the single-event level. Scores rise sharply when multiple signals fire together, which is by design — the RFC's goal is to reduce false positives by requiring multiple signals before high-severity classification.

---

## Possible Future Improvements

| Area | Improvement |
|---|---|
| Correlation | Add a user-behavior rule when the dataset contains repeat users |
| Correlation | Support configurable rules via a YAML/JSON config file |
| Scoring | Load signal weights from external config to allow tuning without code changes |
| Output | Add JSON and SIEM-compatible (CEF/LEEF) output formats |
| Output | Generate a summary HTML report with incident counts by severity |
| Observability | Emit structured JSON logs for ingestion into Cloud Logging |
| Testing | Add unit tests for parser coercions, scorer signals, and correlator rules |
| Scale | Stream large files instead of loading into memory (for logs >1 GB) |
