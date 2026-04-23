# NetSentinel Lab

NetSentinel Lab is a cloud-native defensive lab built to ingest security events, store them in PostgreSQL, and later correlate them into incidents.

## Current scope

This first version includes:

- FastAPI service
- PostgreSQL database
- Docker Compose environment
- Health check with real database validation
- Base data model for events and incidents
- GitHub Actions CI

## Stack

- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- Docker Compose
- GitHub Actions

## Project structure

```text
app/
  api/
  core/
  db/
docker/
infra/
tests/