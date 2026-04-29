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
- Generic event ingestion endpoint
- Falco-compatible ingestion endpoint
- Suricata-compatible ingestion endpoint
- Event listing endpoint
- Event lookup by ID
- Automatic incident creation for high-severity events
- Source-aware incident correlation
- Incident severity escalation
- Incident reopening on recurring activity
- Configurable temporal correlation window
- Multi-event burst correlation for repeated medium activity
- Cross-event attack-chain correlation
- Incident listing endpoint
- Incident lookup by ID
- Incident-to-events lookup endpoint
- Incident detail endpoint with linked events
- Incident timeline endpoint
- Incident enrichment endpoint
- Summary statistics endpoint
- Manual incident status updates
- Filtering for events and incidents
- Pagination and configurable sorting
- Sample event simulation script
- Automated tests with pytest
- GitHub Actions CI

---

## Why this project

NetSentinel Lab was built to simulate part of a defensive security workflow in a simple but realistic way.

It receives security events such as:

- suspicious process execution
- reverse shell detections
- credential access attempts
- simulated port scans
- Falco-style runtime alerts
- Suricata-style network alerts

Then it applies correlation rules that can:

- create incidents for `high` and `critical` events
- keep different telemetry sources separated during correlation
- escalate incident severity if a more severe event arrives later
- reopen a previously closed incident when matching activity appears again
- create a new incident if matching activity is outside the configured correlation window
- promote repeated `medium` events into a `high` incident when they happen as a burst
- elevate incidents to `critical` when a suspicious sequence of different event types is detected

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
```

### Main folders

- `app/api/routes/`  
  API endpoints

- `app/api/schemas/`  
  Pydantic request and response models

- `app/core/`  
  Configuration and app settings

- `app/db/`  
  Database session and ORM models

- `app/services/`  
  Correlation logic and business rules

- `lab/sample_events/`  
  Example event payloads used for simulation

- `scripts/`  
  Utility scripts such as event senders

- `tests/`  
  API and database behavior tests

---

## Features

### 1. Generic event ingestion

The API accepts normalized security events through:

- `POST /events/ingest`

Each event is stored in PostgreSQL with metadata such as:

- source
- event type
- severity
- hostname
- container name
- raw event JSON
- creation timestamp

### 2. Falco-compatible ingestion

The API also accepts Falco-style payloads through:

- `POST /events/ingest/falco`

This endpoint normalizes:

- `rule` into internal `event_type`
- `priority` into internal `severity`
- Falco `output_fields` into `hostname` and `container_name`

### 3. Suricata-compatible ingestion

The API also accepts Suricata-style payloads through:

- `POST /events/ingest/suricata`

This endpoint normalizes:

- Suricata `alert.signature` into internal `event_type`
- Suricata `alert.severity` into internal `severity`
- host and network context into the existing normalized event fields
- the original payload into `raw_event_json`

### 4. Advanced incident correlation

The correlator supports:

- creation of incidents for `high` and `critical` events
- source-aware matching
- severity escalation when a stronger event appears
- reopening of a matching closed incident
- automatic `last_seen` updates
- a configurable temporal window for incident reuse
- burst-based creation of incidents from repeated `medium` events
- sequence-based escalation for suspicious chains of different event types

### 5. Investigation workflow

The API supports querying:

- all events
- a single event by ID
- all incidents
- a single incident by ID
- all events associated with a given incident
- a detailed incident view with linked events
- a chronological incident timeline
- an enriched incident summary

### 6. Event simulation

The project includes sample Falco-style and simulated events plus a script to send them into the API automatically.

### 7. Summary statistics

The API exposes a summary endpoint to inspect the current state of the lab.

It includes:

- total events
- total incidents
- open incidents
- incidents by severity
- events by source

### 8. Manual incident lifecycle updates

The API allows incident status changes through a manual update endpoint.

Current supported states:

- `open`
- `closed`

### 9. Filtering support

The API supports filtering for investigation workflows.

Current filters include:

- events by `severity`
- events by `source`
- events by `event_type`
- events by `hostname`
- events by `container_name`
- incidents by `status`
- incidents by `severity`
- incidents by partial title match

### 10. Pagination and sorting

The API supports pagination and configurable sorting for list endpoints.

Current capabilities include:

- `limit` and `offset` for events
- `limit` and `offset` for incidents
- event sorting by:
  - `created_at`
  - `source`
  - `event_type`
  - `hostname`
  - `container_name`
- incident sorting by:
  - `last_seen`
  - `first_seen`
  - `title`
  - `status`
  - `severity`

### 11. Incident detail view

The API exposes a detailed incident endpoint that returns:

- incident metadata
- related events
- total linked event count

### 12. Incident timeline view

The API exposes a chronological incident timeline endpoint that returns:

- incident metadata
- linked events ordered from oldest to newest
- a compact summary for each event
- total linked event count

### 13. Incident enrichment view

The API exposes an enrichment endpoint that summarizes an incident with:

- sources seen
- severities seen
- hosts seen
- containers seen
- event types seen
- first activity time
- last activity time
- counts by source
- counts by severity
- counts by event type

---

## API endpoints

### Root and health

- `GET /`
- `GET /health`

### Events

- `POST /events/ingest`
- `POST /events/ingest/falco`
- `POST /events/ingest/suricata`
- `GET /events`
- `GET /events/{id}`

### Incidents

- `GET /incidents`
- `GET /incidents/{id}`
- `GET /incidents/{id}/events`
- `GET /incidents/{id}/detail`
- `GET /incidents/{id}/timeline`
- `GET /incidents/{id}/enrichment`
- `PATCH /incidents/{id}`

### Stats

- `GET /stats/summary`

---

## Example workflow

1. Start PostgreSQL and the API
2. Send generic, Falco-style, or Suricata-style events
3. Query stored events
4. Query generated incidents
5. Inspect which events belong to each incident
6. Retrieve summary statistics from the lab
7. Manually close incidents when needed
8. Filter, paginate, and sort results during investigation
9. Retrieve full incident detail with linked events
10. Reconstruct the incident sequence using the timeline endpoint
11. Inspect summarized context with the enrichment endpoint

---

## Local development

### Requirements

You need:

- Python 3.11+
- Docker
- Docker Compose

Python 3.12 is recommended for local development.

---

## Environment configuration

Create the environment file.

### Linux / macOS

```bash
cp .env.example .env
```

### PowerShell

```powershell
Copy-Item .env.example .env -Force
```

Example `.env`:

```env
APP_NAME=NetSentinel Lab API
APP_ENV=development
DATABASE_URL=postgresql+psycopg://netsentinel:netsentinel@localhost:5432/netsentinel
CORRELATION_WINDOW_HOURS=24
```

### Correlation window setting

`CORRELATION_WINDOW_HOURS` controls how long a matching incident remains eligible for reuse.

Examples:

- `24` → reuse incidents active within the last 24 hours
- `1` → only reuse incidents active within the last hour
- `72` → reuse incidents active within the last 3 days

If a matching incident is older than the configured window, a new incident is created.

---

## Run with Docker

To start the full stack:

```bash
docker compose -f infra/docker-compose.yml up --build
```

To run in background:

```bash
docker compose -f infra/docker-compose.yml up -d
```

To stop everything:

```bash
docker compose -f infra/docker-compose.yml down
```

To rebuild containers after code changes:

```bash
docker compose -f infra/docker-compose.yml down
docker compose -f infra/docker-compose.yml up -d --build
```

---

## Application URLs

Once the stack is running:

- API root: `http://localhost:8000/`
- Swagger docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

---

## Install dependencies locally

If you want to run tests or scripts outside Docker:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

On Windows, if `python` does not work, use:

```powershell
py -m pip install --upgrade pip
py -m pip install -e ".[dev]"
```

---

## Run tests

Before running tests locally, make sure PostgreSQL is running:

```powershell
docker compose -f infra/docker-compose.yml up -d db
```

Then run:

```powershell
py -m pytest -q
```

Or:

```bash
python -m pytest -q
```

The test suite covers:

- root endpoint
- health endpoint
- generic event ingestion
- Falco-compatible ingestion
- Suricata-compatible ingestion
- event listing
- event lookup by ID
- incident creation from high-severity events
- incident severity escalation
- incident reopening after closure
- source-aware incident separation
- configurable temporal correlation windows
- multi-event burst correlation for medium events
- cross-event attack-chain correlation
- incident lookup by ID
- incident event lookup
- incident detail endpoint
- incident timeline endpoint
- incident enrichment endpoint
- summary statistics
- manual incident closing
- filtering for events
- filtering for incidents
- pagination and sorting

---

## Generic event ingestion example

```bash
curl -X POST "http://localhost:8000/events/ingest"   -H "Content-Type: application/json"   -d '{
    "source": "falco",
    "event_type": "reverse_shell_detected",
    "severity": "critical",
    "hostname": "node-11",
    "container_name": "api-gateway",
    "raw_event_json": {
      "rule": "Reverse shell detected",
      "priority": "Critical",
      "process": "bash"
    }
  }'
```

---

## Falco ingestion example

```bash
curl -X POST "http://localhost:8000/events/ingest/falco"   -H "Content-Type: application/json"   -d '{
    "output": "A shell was spawned in a container",
    "priority": "Error",
    "rule": "Terminal shell in container",
    "output_fields": {
      "evt.hostname": "node-falco",
      "container.name": "payments-api",
      "proc.name": "bash"
    }
  }'
```

---

## Suricata ingestion example

```bash
curl -X POST "http://localhost:8000/events/ingest/suricata"   -H "Content-Type: application/json"   -d '{
    "timestamp": "2026-04-27T10:48:58.801038Z",
    "event_type": "alert",
    "src_ip": "10.10.0.5",
    "src_port": 51514,
    "dest_ip": "10.10.0.10",
    "dest_port": 443,
    "proto": "TCP",
    "app_proto": "tls",
    "host": "edge-firewall",
    "alert": {
      "signature": "ET MALWARE CnC Beacon Activity",
      "severity": 2
    }
  }'
```

---

## Correlation rules

Current rules now include:

- source-aware correlation
- incident severity escalation
- incident reopening on recurring activity
- configurable temporal correlation windows
- medium-event burst promotion
- attack-chain correlation across event types

### High and critical events

An event creates or updates an incident if:

- severity is `high` or `critical`

### Correlation key

The correlator uses a source-aware matching key so events from different telemetry systems are not merged by mistake.

### Severity escalation

If a matching incident already exists and a more severe event arrives later, the incident severity is raised.

### Reopening behavior

If a matching incident was previously closed and a new relevant event arrives inside the window, the incident is reopened automatically.

### Temporal window

A matching incident is only reused if its `last_seen` is recent enough.

The window is controlled by:

- `CORRELATION_WINDOW_HOURS`

Default:

- `24`

If the last matching activity is older than the configured window, a new incident is created.

### Medium burst promotion

Repeated medium events can also create incidents.

Default rule:

- **3 medium events**
- with the **same source-aware pattern**
- within **15 minutes**

When that happens, the system creates a **high** incident and links the related medium events to it.

### Attack-chain correlation

The correlator also watches for suspicious event sequences.

Current rule:

- `port_scan_detected`
- followed by `credential_access` or `reverse_shell_detected`
- with the same source, host, and container
- within **10 minutes**

When that happens, the incident severity is elevated to **critical**, and the precursor event is linked to the same incident.

### Incident exclusions

Events with severity:

- `low`

are stored only as events for now.

---

## Data model

### `events`

Stores raw security events.

Key fields:

- `id`
- `source`
- `event_type`
- `severity`
- `hostname`
- `container_name`
- `raw_event_json`
- `created_at`

### `incidents`

Stores correlated incidents.

Key fields:

- `id`
- `title`
- `description`
- `severity`
- `status`
- `correlation_key`
- `first_seen`
- `last_seen`

### `incident_events`

Join table linking incidents and events.

Key fields:

- `incident_id`
- `event_id`

---

## CI

This repository includes a GitHub Actions workflow that:

- provisions PostgreSQL
- installs project dependencies
- runs the test suite

This helps verify that the project works in a clean environment and not only on a local machine.

---

## Example use cases

This project can be extended toward:

- Falco event ingestion
- Suricata or Zeek event ingestion
- SOC dashboard backend
- security telemetry pipeline
- Kubernetes security lab
- alert triage system
- incident timeline exploration

---

## Roadmap

Planned improvements:

- configurable medium-burst thresholds
- configurable attack-chain rules
- richer multi-event correlation rules
- normalized adapters for additional network telemetry formats
- attack simulation scenarios
- better incident detail enrichment
- Kubernetes deployment with kind or minikube
- authentication and role-based access
- severity scoring improvements
- dashboard integration

---

## Limitations

This is an early lab implementation, so there are important limitations:

- correlation logic is still intentionally simple
- there is no authentication yet
- there are no database migrations yet
- there is no frontend dashboard yet
- events are ingested manually or from sample scripts


---

## Development notes

This project is structured to grow in layers:

1. stable API foundation
2. persistence
3. correlation logic
4. event simulation
5. investigation endpoints
6. summary and observability features
7. incident lifecycle management
8. filtering support
9. pagination and sorting
10. detailed incident context
11. normalized source adapters
12. chronological incident reconstruction
13. improved correlation behavior
14. configurable temporal windows
15. multi-event burst correlation
16. attack-chain correlation
17. future integrations and orchestration

The focus is not to add unnecessary complexity too early.

---

## License

- MIT License

---

## Author

Built as a portfolio project focused on backend engineering, security event processing, and cloud-native defensive workflows.
