# NetSentinel Lab

NetSentinel Lab is a cloud-native defensive lab built to ingest security events, store them in PostgreSQL, correlate high-severity events into incidents, and expose a clean API for investigation workflows.

This project is designed as a practical portfolio piece focused on:

- security event ingestion
- basic detection correlation
- incident creation
- event-to-incident investigation
- reproducible local environments with Docker
- backend engineering with Python, FastAPI, PostgreSQL, and SQLAlchemy

---

## Current scope

This version includes:

- FastAPI service
- PostgreSQL database
- Docker Compose environment
- Health check with real database validation
- Event ingestion endpoint
- Event listing endpoint
- Event lookup by ID
- Automatic incident creation for high-severity events
- Incident listing endpoint
- Incident lookup by ID
- Incident-to-events lookup endpoint
- Summary statistics endpoint
- Manual incident status updates
- Filtering for events and incidents
- Sample event simulation script
- Automated tests with pytest
- GitHub Actions CI
- Pagination and configurable sorting

---

## Why this project

NetSentinel Lab was built to simulate part of a defensive security workflow in a simple but realistic way.

It receives security events such as:

- suspicious process execution
- reverse shell detections
- credential access attempts
- simulated port scans

Then it applies a basic correlation rule set:

- `high` and `critical` events create or update incidents
- `low` and `medium` events are stored but do not create incidents yet

This makes the project useful as a starting point for a future SOC-style lab, incident analysis service, or cloud-native security platform.

---

## Tech stack

- **Python**
- **FastAPI**
- **PostgreSQL**
- **SQLAlchemy**
- **Docker Compose**
- **pytest**
- **GitHub Actions**

---

## Project structure

```text
netsentinel-lab/
├─ app/
│  ├─ api/
│  │  ├─ routes/
│  │  └─ schemas/
│  ├─ core/
│  ├─ db/
│  └─ services/
├─ docker/
├─ infra/
├─ lab/
│  └─ sample_events/
├─ scripts/
├─ tests/
└─ .github/
   └─ workflows/