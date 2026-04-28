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
- Incident listing endpoint
- Incident lookup by ID
- Incident-to-events lookup endpoint
- Incident detail endpoint with linked events
- Incident timeline endpoint
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

This makes the project more realistic because it can ingest a format closer to a real runtime security tool.

### 3. Suricata-compatible ingestion

The API also accepts Suricata-style payloads through:

- `POST /events/ingest/suricata`

This endpoint normalizes:

- Suricata `alert.signature` into internal `event_type`
- Suricata `alert.severity` into internal `severity`
- host and network context into the existing normalized event fields
- the original payload into `raw_event_json`

This makes the project more relevant to network security workflows, not only runtime security.

### 4. Incident correlation

A simple rule-based correlator automatically evaluates new events.

Current correlation logic:

- `high` and `critical` severity events create or update incidents
- incidents are grouped by:
  - `event_type`
  - `hostname`
  - `container_name`

This means repeated high-severity events affecting the same normalized target are grouped under the same open incident.

### 5. Investigation workflow

The API supports querying:

- all events
- a single event by ID
- all incidents
- a single incident by ID
- all events associated with a given incident
- a detailed incident view with linked events
- a chronological incident timeline

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

This makes the project more realistic by supporting basic incident lifecycle management instead of only automatic creation.

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

This is useful for investigation workflows because it provides context in a single response instead of forcing clients to call multiple endpoints separately.

### 12. Incident timeline view

The API exposes a chronological incident timeline endpoint that returns:

- incident metadata
- linked events ordered from oldest to newest
- a compact summary for each event
- total linked event count

This is useful when reconstructing how an incident evolved over time.

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
```

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
- no incident creation from medium-severity events
- incident lookup by ID
- incident event lookup
- incident detail endpoint
- incident timeline endpoint
- repeated event correlation into a single incident
- summary statistics
- manual incident closing
- filtering for events
- filtering for incidents
- pagination and sorting

---

## Generic event ingestion example

You can send a normalized event manually with `curl`:

```bash
curl -X POST "http://localhost:8000/events/ingest" \
  -H "Content-Type: application/json" \
  -d '{
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

You can also send a Falco-style payload:

```bash
curl -X POST "http://localhost:8000/events/ingest/falco" \
  -H "Content-Type: application/json" \
  -d '{
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

Expected normalization:

- `source` becomes `falco`
- `event_type` becomes `terminal_shell_in_container`
- `priority=Error` maps to `severity=high`
- `evt.hostname` maps to `hostname`
- `container.name` maps to `container_name`

---

## Suricata ingestion example

You can also send a Suricata-style payload:

```bash
curl -X POST "http://localhost:8000/events/ingest/suricata" \
  -H "Content-Type: application/json" \
  -d '{
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

Expected normalization:

- `source` becomes `suricata`
- `event_type` becomes `et_malware_cnc_beacon_activity`
- `alert.severity=2` maps to `severity=high`
- `host` maps to `hostname`
- `app_proto` or `proto` maps into the normalized context field used by the API

---

## Send sample events

The project includes sample events in:

```text
lab/sample_events/falco_samples.json
```

To send them to the running API:

```bash
python scripts/send_sample_events.py
```

You can also provide a custom base URL:

```bash
python scripts/send_sample_events.py http://localhost:8000
```

---

## Example investigation flow

After sending sample events, inspect the API.

### List events

```bash
curl http://localhost:8000/events
```

### List incidents

```bash
curl http://localhost:8000/incidents
```

### Get a single incident

```bash
curl http://localhost:8000/incidents/1
```

### Get all events linked to an incident

```bash
curl http://localhost:8000/incidents/1/events
```

### Get incident detail with linked events

```bash
curl http://localhost:8000/incidents/1/detail
```

### Get incident timeline

```bash
curl http://localhost:8000/incidents/1/timeline
```

### Get summary statistics

```bash
curl http://localhost:8000/stats/summary
```

### Close an incident

```bash
curl -X PATCH "http://localhost:8000/incidents/1" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "closed"
  }'
```

---

## Filtering examples

### Filter events by source and severity

```bash
curl "http://localhost:8000/events?source=falco&severity=critical"
```

### Filter events by event type

```bash
curl "http://localhost:8000/events?event_type=credential_access"
```

### Filter events by hostname

```bash
curl "http://localhost:8000/events?hostname=node-11"
```

### Filter events by container name

```bash
curl "http://localhost:8000/events?container_name=api-gateway"
```

### Filter incidents by status and severity

```bash
curl "http://localhost:8000/incidents?status=open&severity=high"
```

### Filter incidents by title

```bash
curl "http://localhost:8000/incidents?title_contains=payments-service"
```

---

## Pagination and sorting examples

### Paginate events

```bash
curl "http://localhost:8000/events?limit=2&offset=0"
```

### Sort events by hostname ascending

```bash
curl "http://localhost:8000/events?sort_by=hostname&sort_order=asc"
```

### Paginate incidents

```bash
curl "http://localhost:8000/incidents?limit=2&offset=0"
```

### Sort incidents by title descending

```bash
curl "http://localhost:8000/incidents?sort_by=title&sort_order=desc"
```

---

## Incident detail example

You can retrieve a full incident view with linked events using:

```bash
curl "http://localhost:8000/incidents/1/detail"
```

---

## Incident timeline example

You can retrieve a chronological incident timeline using:

```bash
curl "http://localhost:8000/incidents/1/timeline"
```

---

## Stats summary

You can retrieve a summary of the current lab state with:

```bash
curl http://localhost:8000/stats/summary
```

---

## Manual incident updates

You can manually update the lifecycle status of an incident.

Example request:

```bash
curl -X PATCH "http://localhost:8000/incidents/1" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "closed"
  }'
```

---

## Correlation rules

Current rules are intentionally simple.

### Incident creation

An event creates or updates an incident if:

- severity is `high` or `critical`

### Incident grouping

Events are grouped into the same open incident if they share:

- `event_type`
- `hostname`
- `container_name`

### Incident exclusions

Events with severity:

- `low`
- `medium`

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

- richer correlation rules
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

- correlation logic is intentionally simple
- there is no authentication yet
- there are no database migrations yet
- there is no frontend dashboard yet
- events are ingested manually or from sample scripts
- incident lifecycle management is still basic


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
13. future integrations and orchestration

The focus is not to add unnecessary complexity too early.

---

## License

***

---

## Author

Built as a portfolio project focused on backend engineering, security event processing, and cloud-native defensive workflows.
