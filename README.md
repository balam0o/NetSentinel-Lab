# NetSentinel Lab

NetSentinel Lab is a cloud-native defensive lab built to ingest security events, store them in PostgreSQL, and correlate high-severity events into incidents.

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
- GitHub Actions CI

## Stack

- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- Docker Compose
- GitHub Actions

## Available endpoints

- `GET /`
- `GET /health`
- `POST /events/ingest`
- `GET /events`
- `GET /events/{id}`
- `GET /incidents`
- `GET /incidents/{id}`

## Run locally

```bash
cp .env.example .env
docker compose -f infra/docker-compose.yml up --build