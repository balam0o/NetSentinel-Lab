from datetime import datetime, timedelta, timezone
import app.services.correlator as correlator
from app.db.models import Incident
from app.db.session import SessionLocal
from app.db.models import Event, Incident


def test_root(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["docs"] == "/docs"


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "up"


def test_ingest_event(client):
    payload = {
        "source": "falco",
        "event_type": "suspicious_process",
        "severity": "high",
        "hostname": "node-1",
        "container_name": "lab-nginx",
        "raw_event_json": {
            "rule": "Terminal shell in container",
            "priority": "Warning",
            "output": "A shell was spawned in a container",
        },
    }

    response = client.post("/events/ingest", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["source"] == payload["source"]
    assert data["event_type"] == payload["event_type"]
    assert data["severity"] == payload["severity"]
    assert data["hostname"] == payload["hostname"]
    assert data["container_name"] == payload["container_name"]
    assert data["raw_event_json"]["rule"] == "Terminal shell in container"
    assert "id" in data
    assert "created_at" in data


def test_list_events(client):
    payload = {
        "source": "simulator",
        "event_type": "network_probe",
        "severity": "low",
        "hostname": "node-a",
        "container_name": "sensor-a",
        "raw_event_json": {"message": "probe detected"},
    }
    client.post("/events/ingest", json=payload)

    response = client.get("/events")
    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_get_event_by_id(client):
    create_payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "sensor-1",
        "container_name": "attacker-box",
        "raw_event_json": {
            "src_ip": "10.10.0.5",
            "dst_ip": "10.10.0.10",
            "ports": [22, 80, 443],
        },
    }

    create_response = client.post("/events/ingest", json=create_payload)
    created_event = create_response.json()

    response = client.get(f"/events/{created_event['id']}")
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == created_event["id"]
    assert data["event_type"] == "port_scan_detected"


def test_get_event_not_found(client):
    response = client.get("/events/999999")
    assert response.status_code == 404


def test_high_severity_event_creates_incident(client):
    payload = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-9",
        "container_name": "compromised-api",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "priority": "Critical",
        },
    }

    response = client.post("/events/ingest", json=payload)
    assert response.status_code == 201

    incidents_response = client.get("/incidents")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert isinstance(incidents, list)
    assert len(incidents) >= 1

    matching = [
        incident
        for incident in incidents
        if incident["title"] == "reverse_shell_detected on node-9/compromised-api"
    ]
    assert len(matching) == 1
    assert matching[0]["severity"] == "critical"
    assert matching[0]["status"] == "open"


def test_medium_event_does_not_create_incident(client):
    payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-2",
        "container_name": "scanner-box",
        "raw_event_json": {
            "ports": [21, 22, 80],
        },
    }

    before = client.get("/incidents").json()

    response = client.post("/events/ingest", json=payload)
    assert response.status_code == 201

    after = client.get("/incidents").json()
    assert len(after) == len(before)


def test_get_incident_by_id(client):
    payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-7",
        "container_name": "payments-service",
        "raw_event_json": {
            "file": "/etc/shadow",
        },
    }

    client.post("/events/ingest", json=payload)

    incidents_response = client.get("/incidents")
    incidents = incidents_response.json()

    target = next(
        incident
        for incident in incidents
        if incident["title"] == "credential_access on node-7/payments-service"
    )

    response = client.get(f"/incidents/{target['id']}")
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == target["id"]
    assert data["severity"] == "high"


def test_get_incident_not_found(client):
    response = client.get("/incidents/999999")
    assert response.status_code == 404


def test_get_incident_events(client):
    payload = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-11",
        "container_name": "api-gateway",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "priority": "Critical",
            "process": "bash",
        },
    }

    create_response = client.post("/events/ingest", json=payload)
    created_event = create_response.json()

    incidents_response = client.get("/incidents")
    incidents = incidents_response.json()

    target = next(
        incident
        for incident in incidents
        if incident["title"] == "reverse_shell_detected on node-11/api-gateway"
    )

    response = client.get(f"/incidents/{target['id']}/events")
    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["id"] == created_event["id"]
    assert data[0]["event_type"] == "reverse_shell_detected"


def test_get_incident_events_not_found(client):
    response = client.get("/incidents/999999/events")
    assert response.status_code == 404

def test_multiple_high_severity_events_create_single_incident(client):
    payload_1 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-11",
        "container_name": "api-gateway",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "bash",
        },
    }

    payload_2 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-11",
        "container_name": "api-gateway",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "sh",
        },
    }

    response_1 = client.post("/events/ingest", json=payload_1)
    response_2 = client.post("/events/ingest", json=payload_2)

    assert response_1.status_code == 201
    assert response_2.status_code == 201

    incidents_response = client.get("/incidents")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    matching = [
        incident
        for incident in incidents
        if incident["title"] == "reverse_shell_detected on node-11/api-gateway"
    ]

    assert len(matching) == 1


def test_incident_events_endpoint_returns_multiple_related_events(client):
    payload_1 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-11",
        "container_name": "api-gateway",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "bash",
        },
    }

    payload_2 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-11",
        "container_name": "api-gateway",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "sh",
        },
    }

    client.post("/events/ingest", json=payload_1)
    client.post("/events/ingest", json=payload_2)

    incidents = client.get("/incidents").json()
    target = next(
        incident
        for incident in incidents
        if incident["title"] == "reverse_shell_detected on node-11/api-gateway"
    )

    response = client.get(f"/incidents/{target['id']}/events")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 2
    assert all(event["event_type"] == "reverse_shell_detected" for event in data)

def test_stats_summary(client):
    events = [
        {
            "source": "falco",
            "event_type": "reverse_shell_detected",
            "severity": "critical",
            "hostname": "node-11",
            "container_name": "api-gateway",
            "raw_event_json": {"rule": "Reverse shell detected", "process": "bash"},
        },
        {
            "source": "falco",
            "event_type": "reverse_shell_detected",
            "severity": "critical",
            "hostname": "node-11",
            "container_name": "api-gateway",
            "raw_event_json": {"rule": "Reverse shell detected", "process": "sh"},
        },
        {
            "source": "falco",
            "event_type": "credential_access",
            "severity": "high",
            "hostname": "node-7",
            "container_name": "payments-service",
            "raw_event_json": {"file": "/etc/shadow"},
        },
        {
            "source": "simulator",
            "event_type": "port_scan_detected",
            "severity": "medium",
            "hostname": "node-2",
            "container_name": "scanner-box",
            "raw_event_json": {"ports": [21, 22, 80]},
        },
    ]

    for payload in events:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    response = client.get("/stats/summary")
    assert response.status_code == 200

    data = response.json()
    assert data["total_events"] == 4
    assert data["total_incidents"] == 2
    assert data["open_incidents"] == 2
    assert data["incidents_by_severity"]["critical"] == 1
    assert data["incidents_by_severity"]["high"] == 1
    assert data["events_by_source"]["falco"] == 3
    assert data["events_by_source"]["simulator"] == 1

def test_close_incident(client):
    payload = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-20",
        "container_name": "web-api",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "bash",
        },
    }

    create_response = client.post("/events/ingest", json=payload)
    assert create_response.status_code == 201

    incidents_response = client.get("/incidents")
    incidents = incidents_response.json()

    target = next(
        incident
        for incident in incidents
        if incident["title"] == "reverse_shell_detected on node-20/web-api"
    )

    patch_response = client.patch(
        f"/incidents/{target['id']}",
        json={"status": "closed"},
    )
    assert patch_response.status_code == 200

    updated = patch_response.json()
    assert updated["id"] == target["id"]
    assert updated["status"] == "closed"


def test_patch_incident_not_found(client):
    response = client.patch(
        "/incidents/999999",
        json={"status": "closed"},
    )
    assert response.status_code == 404


def test_stats_summary_reflects_closed_incident(client):
    payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-30",
        "container_name": "billing-service",
        "raw_event_json": {
            "file": "/etc/shadow",
        },
    }

    create_response = client.post("/events/ingest", json=payload)
    assert create_response.status_code == 201

    incidents_response = client.get("/incidents")
    incidents = incidents_response.json()

    target = next(
        incident
        for incident in incidents
        if incident["title"] == "credential_access on node-30/billing-service"
    )

    close_response = client.patch(
        f"/incidents/{target['id']}",
        json={"status": "closed"},
    )
    assert close_response.status_code == 200

    stats_response = client.get("/stats/summary")
    assert stats_response.status_code == 200

    stats = stats_response.json()
    assert stats["total_incidents"] == 1
    assert stats["open_incidents"] == 0

def test_filter_events_by_source_and_severity(client):
    events = [
        {
            "source": "falco",
            "event_type": "reverse_shell_detected",
            "severity": "critical",
            "hostname": "node-1",
            "container_name": "api-gateway",
            "raw_event_json": {"rule": "Reverse shell detected"},
        },
        {
            "source": "simulator",
            "event_type": "port_scan_detected",
            "severity": "medium",
            "hostname": "node-2",
            "container_name": "scanner-box",
            "raw_event_json": {"ports": [21, 22, 80]},
        },
        {
            "source": "falco",
            "event_type": "credential_access",
            "severity": "high",
            "hostname": "node-3",
            "container_name": "payments-service",
            "raw_event_json": {"file": "/etc/shadow"},
        },
    ]

    for payload in events:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    response = client.get("/events?source=falco&severity=critical")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 1
    assert data[0]["source"] == "falco"
    assert data[0]["severity"] == "critical"
    assert data[0]["event_type"] == "reverse_shell_detected"


def test_filter_events_by_event_type(client):
    events = [
        {
            "source": "falco",
            "event_type": "suspicious_process",
            "severity": "high",
            "hostname": "node-a",
            "container_name": "container-a",
            "raw_event_json": {"process": "nc"},
        },
        {
            "source": "falco",
            "event_type": "credential_access",
            "severity": "high",
            "hostname": "node-b",
            "container_name": "container-b",
            "raw_event_json": {"file": "/etc/shadow"},
        },
    ]

    for payload in events:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    response = client.get("/events?event_type=credential_access")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 1
    assert data[0]["event_type"] == "credential_access"


def test_filter_incidents_by_status_and_severity(client):
    critical_payload = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-20",
        "container_name": "web-api",
        "raw_event_json": {"rule": "Reverse shell detected"},
    }

    high_payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-21",
        "container_name": "billing-service",
        "raw_event_json": {"file": "/etc/shadow"},
    }

    client.post("/events/ingest", json=critical_payload)
    client.post("/events/ingest", json=high_payload)

    incidents = client.get("/incidents").json()

    critical_incident = next(
        incident
        for incident in incidents
        if incident["title"] == "reverse_shell_detected on node-20/web-api"
    )

    close_response = client.patch(
        f"/incidents/{critical_incident['id']}",
        json={"status": "closed"},
    )
    assert close_response.status_code == 200

    response = client.get("/incidents?status=closed&severity=critical")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 1
    assert data[0]["status"] == "closed"
    assert data[0]["severity"] == "critical"
    assert data[0]["title"] == "reverse_shell_detected on node-20/web-api"


def test_filter_incidents_by_title_contains(client):
    payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-30",
        "container_name": "payments-service",
        "raw_event_json": {"file": "/etc/shadow"},
    }

    response = client.post("/events/ingest", json=payload)
    assert response.status_code == 201

    response = client.get("/incidents?title_contains=payments-service")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 1
    assert "payments-service" in data[0]["title"]

def test_paginate_events_with_limit_and_offset(client):
    payloads = [
        {
            "source": "falco",
            "event_type": f"event_{index}",
            "severity": "high",
            "hostname": f"node-{index}",
            "container_name": f"container-{index}",
            "raw_event_json": {"index": index},
        }
        for index in range(3)
    ]

    for payload in payloads:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    response = client.get("/events?sort_by=event_type&sort_order=asc&limit=1&offset=1")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 1
    assert data[0]["event_type"] == "event_1"


def test_sort_events_by_hostname_ascending(client):
    payloads = [
        {
            "source": "falco",
            "event_type": "credential_access",
            "severity": "high",
            "hostname": "node-z",
            "container_name": "container-a",
            "raw_event_json": {"file": "/etc/shadow"},
        },
        {
            "source": "falco",
            "event_type": "credential_access",
            "severity": "high",
            "hostname": "node-a",
            "container_name": "container-b",
            "raw_event_json": {"file": "/etc/passwd"},
        },
    ]

    for payload in payloads:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    response = client.get("/events?sort_by=hostname&sort_order=asc")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 2
    assert data[0]["hostname"] == "node-a"
    assert data[1]["hostname"] == "node-z"


def test_paginate_incidents_with_limit_and_offset(client):
    payloads = [
        {
            "source": "falco",
            "event_type": f"incident_type_{index}",
            "severity": "high",
            "hostname": f"node-{index}",
            "container_name": f"service-{index}",
            "raw_event_json": {"index": index},
        }
        for index in range(3)
    ]

    for payload in payloads:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    response = client.get("/incidents?sort_by=title&sort_order=asc&limit=1&offset=1")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "incident_type_1 on node-1/service-1"


def test_sort_incidents_by_title_descending(client):
    payloads = [
        {
            "source": "falco",
            "event_type": "aaa_event",
            "severity": "high",
            "hostname": "node-1",
            "container_name": "service-1",
            "raw_event_json": {"index": 1},
        },
        {
            "source": "falco",
            "event_type": "zzz_event",
            "severity": "high",
            "hostname": "node-2",
            "container_name": "service-2",
            "raw_event_json": {"index": 2},
        },
    ]

    for payload in payloads:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    response = client.get("/incidents?sort_by=title&sort_order=desc")
    assert response.status_code == 200

    data = response.json()
    assert len(data) == 2
    assert data[0]["title"] == "zzz_event on node-2/service-2"
    assert data[1]["title"] == "aaa_event on node-1/service-1"

def test_get_incident_detail(client):
    payload_1 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-99",
        "container_name": "gateway-service",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "bash",
        },
    }

    payload_2 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-99",
        "container_name": "gateway-service",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "sh",
        },
    }

    response_1 = client.post("/events/ingest", json=payload_1)
    response_2 = client.post("/events/ingest", json=payload_2)

    assert response_1.status_code == 201
    assert response_2.status_code == 201

    incidents_response = client.get(
        "/incidents?title_contains=gateway-service&sort_by=title&sort_order=asc"
    )
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    detail_response = client.get(f"/incidents/{incident_id}/detail")
    assert detail_response.status_code == 200

    data = detail_response.json()
    assert data["incident"]["id"] == incident_id
    assert data["incident"]["title"] == "reverse_shell_detected on node-99/gateway-service"
    assert data["event_count"] == 2
    assert len(data["events"]) == 2
    assert all(event["event_type"] == "reverse_shell_detected" for event in data["events"])


def test_get_incident_detail_not_found(client):
    response = client.get("/incidents/999999/detail")
    assert response.status_code == 404

def test_ingest_falco_event_adapter(client):
    payload = {
        "output": "A shell was spawned in a container",
        "priority": "Error",
        "rule": "Terminal shell in container",
        "output_fields": {
            "evt.hostname": "node-falco",
            "container.name": "payments-api",
            "proc.name": "bash",
        },
    }

    response = client.post("/events/ingest/falco", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["source"] == "falco"
    assert data["event_type"] == "terminal_shell_in_container"
    assert data["severity"] == "high"
    assert data["hostname"] == "node-falco"
    assert data["container_name"] == "payments-api"
    assert data["raw_event_json"]["rule"] == "Terminal shell in container"
    assert data["raw_event_json"]["priority"] == "Error"


def test_falco_ingestion_creates_incident_for_high_priority(client):
    payload = {
        "output": "A shell was spawned in a container",
        "priority": "Error",
        "rule": "Terminal shell in container",
        "output_fields": {
            "evt.hostname": "node-falco",
            "container.name": "payments-api",
        },
    }

    response = client.post("/events/ingest/falco", json=payload)
    assert response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=payments-api")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 1
    assert incidents[0]["title"] == "terminal_shell_in_container on node-falco/payments-api"
    assert incidents[0]["severity"] == "high"


def test_falco_warning_maps_to_medium_and_does_not_create_incident(client):
    payload = {
        "output": "Unexpected process detected",
        "priority": "Warning",
        "rule": "Suspicious process",
        "output_fields": {
            "evt.hostname": "node-warning",
            "container.name": "worker-service",
        },
    }

    response = client.post("/events/ingest/falco", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["severity"] == "medium"

    incidents_response = client.get("/incidents?title_contains=worker-service")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()
    assert len(incidents) == 0

def test_get_incident_timeline(client):
    payload_1 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-timeline",
        "container_name": "gateway-service",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "bash",
        },
    }

    payload_2 = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-timeline",
        "container_name": "gateway-service",
        "raw_event_json": {
            "rule": "Reverse shell detected",
            "process": "sh",
        },
    }

    response_1 = client.post("/events/ingest", json=payload_1)
    response_2 = client.post("/events/ingest", json=payload_2)

    assert response_1.status_code == 201
    assert response_2.status_code == 201

    event_1 = response_1.json()
    event_2 = response_2.json()

    incidents_response = client.get(
        "/incidents?title_contains=gateway-service&sort_by=title&sort_order=asc"
    )
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    timeline_response = client.get(f"/incidents/{incident_id}/timeline")
    assert timeline_response.status_code == 200

    data = timeline_response.json()
    assert data["incident"]["id"] == incident_id
    assert data["event_count"] == 2
    assert len(data["timeline"]) == 2
    assert data["timeline"][0]["event_id"] == event_1["id"]
    assert data["timeline"][1]["event_id"] == event_2["id"]
    assert data["timeline"][0]["summary"] == "Reverse shell detected"


def test_get_incident_timeline_not_found(client):
    response = client.get("/incidents/999999/timeline")
    assert response.status_code == 404


def test_falco_timeline_summary_uses_output_when_rule_not_present_in_raw(client):
    payload = {
        "output": "Unexpected outbound connection from container",
        "priority": "Error",
        "rule": "Outbound connection",
        "output_fields": {
            "evt.hostname": "node-falco-timeline",
            "container.name": "network-proxy",
        },
    }

    create_response = client.post("/events/ingest/falco", json=payload)
    assert create_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=network-proxy")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    timeline_response = client.get(f"/incidents/{incident_id}/timeline")
    assert timeline_response.status_code == 200

    data = timeline_response.json()
    assert data["event_count"] == 1
    assert data["timeline"][0]["summary"] == "Outbound connection"

def test_ingest_suricata_event_adapter(client):
    payload = {
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
    }

    response = client.post("/events/ingest/suricata", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["source"] == "suricata"
    assert data["event_type"] == "et_malware_cnc_beacon_activity"
    assert data["severity"] == "high"
    assert data["hostname"] == "edge-firewall"
    assert data["container_name"] == "tls"
    assert data["raw_event_json"]["dest_ip"] == "10.10.0.10"


def test_suricata_ingestion_creates_incident_for_high_severity(client):
    payload = {
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
    }

    response = client.post("/events/ingest/suricata", json=payload)
    assert response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=edge-firewall")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 1
    assert incidents[0]["title"] == "et_malware_cnc_beacon_activity on edge-firewall/tls"
    assert incidents[0]["severity"] == "high"


def test_suricata_medium_severity_does_not_create_incident(client):
    payload = {
        "timestamp": "2026-04-27T10:48:58.801038Z",
        "event_type": "alert",
        "src_ip": "10.10.0.20",
        "src_port": 44444,
        "dest_ip": "10.10.0.30",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "host": "web-sensor",
        "alert": {
            "signature": "ET POLICY Suspicious User Agent",
            "severity": 3
        }
    }

    response = client.post("/events/ingest/suricata", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["severity"] == "medium"

    incidents_response = client.get("/incidents?title_contains=web-sensor")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()
    assert len(incidents) == 0

def test_get_incident_enrichment(client):
    payloads = [
        {
            "source": "falco",
            "event_type": "reverse_shell_detected",
            "severity": "critical",
            "hostname": "node-enrich",
            "container_name": "gateway-service",
            "raw_event_json": {
                "rule": "Reverse shell detected",
                "process": "bash",
            },
        },
        {
            "source": "falco",
            "event_type": "reverse_shell_detected",
            "severity": "high",
            "hostname": "node-enrich",
            "container_name": "gateway-service",
            "raw_event_json": {
                "message": "Outbound malicious traffic detected",
            },
        },
    ]

    for payload in payloads:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=gateway-service")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    enrichment_response = client.get(f"/incidents/{incident_id}/enrichment")
    assert enrichment_response.status_code == 200

    data = enrichment_response.json()
    assert data["incident"]["id"] == incident_id
    assert data["event_count"] == 2
    assert data["sources_seen"] == ["falco"]
    assert data["hosts_seen"] == ["node-enrich"]
    assert data["containers_seen"] == ["gateway-service"]
    assert data["event_types_seen"] == ["reverse_shell_detected"]
    assert data["counts_by_source"]["falco"] == 2
    assert data["counts_by_severity"]["critical"] == 1
    assert data["counts_by_severity"]["high"] == 1
    assert data["counts_by_event_type"]["reverse_shell_detected"] == 2
    assert data["first_activity"] is not None
    assert data["last_activity"] is not None

def test_get_incident_enrichment_not_found(client):
    response = client.get("/incidents/999999/enrichment")
    assert response.status_code == 404


def test_enrichment_sorted_unique_values(client):
    payloads = [
        {
            "source": "falco",
            "event_type": "credential_access",
            "severity": "high",
            "hostname": "node-b",
            "container_name": "service-z",
            "raw_event_json": {"rule": "Sensitive file opened"},
        },
        {
            "source": "falco",
            "event_type": "credential_access",
            "severity": "high",
            "hostname": "node-a",
            "container_name": "service-a",
            "raw_event_json": {"rule": "Sensitive file opened"},
        },
    ]

    for payload in payloads:
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=credential_access")
    incidents = incidents_response.json()
    assert len(incidents) == 2

    target = next(
        incident for incident in incidents if incident["title"] == "credential_access on node-a/service-a"
    )

    enrichment_response = client.get(f"/incidents/{target['id']}/enrichment")
    assert enrichment_response.status_code == 200

    data = enrichment_response.json()
    assert data["hosts_seen"] == ["node-a"]
    assert data["containers_seen"] == ["service-a"]

def test_incident_severity_escalates_when_more_severe_event_arrives(client):
    first_payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-escalate",
        "container_name": "billing-api",
        "raw_event_json": {"rule": "Sensitive file opened"},
    }

    second_payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "critical",
        "hostname": "node-escalate",
        "container_name": "billing-api",
        "raw_event_json": {"rule": "Sensitive file opened again"},
    }

    first_response = client.post("/events/ingest", json=first_payload)
    second_response = client.post("/events/ingest", json=second_payload)

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=billing-api")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "critical"


def test_closed_incident_reopens_on_new_matching_event(client):
    payload = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-reopen",
        "container_name": "gateway-api",
        "raw_event_json": {"rule": "Reverse shell detected"},
    }

    first_response = client.post("/events/ingest", json=payload)
    assert first_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=gateway-api")
    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    close_response = client.patch(
        f"/incidents/{incident_id}",
        json={"status": "closed"},
    )
    assert close_response.status_code == 200
    assert close_response.json()["status"] == "closed"

    second_response = client.post("/events/ingest", json=payload)
    assert second_response.status_code == 201

    refreshed_response = client.get(f"/incidents/{incident_id}")
    assert refreshed_response.status_code == 200
    assert refreshed_response.json()["status"] == "open"


def test_same_pattern_from_different_sources_creates_separate_incidents(client):
    falco_payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-split",
        "container_name": "payments-api",
        "raw_event_json": {"rule": "Sensitive file opened"},
    }

    suricata_payload = {
        "source": "suricata",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-split",
        "container_name": "payments-api",
        "raw_event_json": {"message": "Sensitive network activity"},
    }

    falco_response = client.post("/events/ingest", json=falco_payload)
    suricata_response = client.post("/events/ingest", json=suricata_payload)

    assert falco_response.status_code == 201
    assert suricata_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=payments-api")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 2

def test_matching_event_outside_correlation_window_creates_new_incident(client):
    payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-window",
        "container_name": "billing-api",
        "raw_event_json": {"rule": "Sensitive file opened"},
    }

    first_response = client.post("/events/ingest", json=payload)
    assert first_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=billing-api")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()
    assert len(incidents) == 1

    original_incident_id = incidents[0]["id"]

    with SessionLocal() as db:
        incident = db.get(Incident, original_incident_id)
        incident.first_seen = datetime.now(timezone.utc) - timedelta(days=2, minutes=5)
        incident.last_seen = datetime.now(timezone.utc) - timedelta(days=2)
        db.commit()

    second_response = client.post("/events/ingest", json=payload)
    assert second_response.status_code == 201

    refreshed_response = client.get("/incidents?title_contains=billing-api")
    assert refreshed_response.status_code == 200
    refreshed_incidents = refreshed_response.json()

    assert len(refreshed_incidents) == 2
    ids = {incident["id"] for incident in refreshed_incidents}
    assert original_incident_id in ids


def test_old_closed_incident_outside_window_creates_new_incident(client):
    payload = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-old-window",
        "container_name": "gateway-api",
        "raw_event_json": {"rule": "Reverse shell detected"},
    }

    create_response = client.post("/events/ingest", json=payload)
    assert create_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=gateway-api")
    incidents = incidents_response.json()
    assert len(incidents) == 1

    original_incident_id = incidents[0]["id"]

    close_response = client.patch(
        f"/incidents/{original_incident_id}",
        json={"status": "closed"},
    )
    assert close_response.status_code == 200

    with SessionLocal() as db:
        incident = db.get(Incident, original_incident_id)
        incident.first_seen = datetime.now(timezone.utc) - timedelta(days=3, minutes=5)
        incident.last_seen = datetime.now(timezone.utc) - timedelta(days=3)
        db.commit()

    second_response = client.post("/events/ingest", json=payload)
    assert second_response.status_code == 201

    refreshed_response = client.get("/incidents?title_contains=gateway-api")
    assert refreshed_response.status_code == 200
    refreshed_incidents = refreshed_response.json()

    assert len(refreshed_incidents) == 2
    statuses = sorted(incident["status"] for incident in refreshed_incidents)
    assert statuses == ["closed", "open"]

def test_configurable_short_correlation_window_creates_new_incident(client, monkeypatch):
    monkeypatch.setattr(correlator, "get_correlation_window_hours", lambda: 1)

    payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-config-window",
        "container_name": "billing-api",
        "raw_event_json": {"rule": "Sensitive file opened"},
    }

    first_response = client.post("/events/ingest", json=payload)
    assert first_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=billing-api")
    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        incident.first_seen = datetime.now(timezone.utc) - timedelta(hours=2, minutes=5)
        incident.last_seen = datetime.now(timezone.utc) - timedelta(hours=2)
        db.commit()

    second_response = client.post("/events/ingest", json=payload)
    assert second_response.status_code == 201

    refreshed_response = client.get("/incidents?title_contains=billing-api")
    refreshed_incidents = refreshed_response.json()
    assert len(refreshed_incidents) == 2


def test_configurable_long_correlation_window_reuses_incident(client, monkeypatch):
    monkeypatch.setattr(correlator, "get_correlation_window_hours", lambda: 72)

    payload = {
        "source": "falco",
        "event_type": "reverse_shell_detected",
        "severity": "critical",
        "hostname": "node-long-window",
        "container_name": "gateway-api",
        "raw_event_json": {"rule": "Reverse shell detected"},
    }

    first_response = client.post("/events/ingest", json=payload)
    assert first_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=gateway-api")
    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        incident.first_seen = datetime.now(timezone.utc) - timedelta(hours=48, minutes=5)
        incident.last_seen = datetime.now(timezone.utc) - timedelta(hours=48)
        db.commit()

    second_response = client.post("/events/ingest", json=payload)
    assert second_response.status_code == 201

    refreshed_response = client.get("/incidents?title_contains=gateway-api")
    refreshed_incidents = refreshed_response.json()
    assert len(refreshed_incidents) == 1

def test_repeated_medium_events_create_incident_after_threshold(client):
    payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-burst",
        "container_name": "scanner-box",
        "raw_event_json": {"ports": [21, 22, 80]},
    }

    response_1 = client.post("/events/ingest", json=payload)
    response_2 = client.post("/events/ingest", json=payload)

    assert response_1.status_code == 201
    assert response_2.status_code == 201

    before_response = client.get("/incidents?title_contains=scanner-box")
    assert before_response.status_code == 200
    assert len(before_response.json()) == 0

    response_3 = client.post("/events/ingest", json=payload)
    assert response_3.status_code == 201

    incidents_response = client.get("/incidents?title_contains=scanner-box")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 1
    assert incidents[0]["title"] == "port_scan_detected on node-burst/scanner-box"
    assert incidents[0]["severity"] == "high"

    incident_id = incidents[0]["id"]

    related_events_response = client.get(f"/incidents/{incident_id}/events")
    assert related_events_response.status_code == 200
    related_events = related_events_response.json()
    assert len(related_events) == 3
    assert all(event["severity"] == "medium" for event in related_events)


def test_medium_burst_correlation_is_source_aware(client):
    falco_payload = {
        "source": "falco",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-source-burst",
        "container_name": "scanner-box",
        "raw_event_json": {"rule": "Port scan detected"},
    }

    suricata_payload = {
        "source": "suricata",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-source-burst",
        "container_name": "scanner-box",
        "raw_event_json": {"message": "Port scan detected"},
    }

    assert client.post("/events/ingest", json=falco_payload).status_code == 201
    assert client.post("/events/ingest", json=falco_payload).status_code == 201
    assert client.post("/events/ingest", json=suricata_payload).status_code == 201

    incidents_response = client.get("/incidents?title_contains=scanner-box")
    assert incidents_response.status_code == 200
    assert len(incidents_response.json()) == 0

    assert client.post("/events/ingest", json=falco_payload).status_code == 201

    refreshed_response = client.get("/incidents?title_contains=scanner-box")
    assert refreshed_response.status_code == 200
    incidents = refreshed_response.json()

    assert len(incidents) == 1
    assert incidents[0]["title"] == "port_scan_detected on node-source-burst/scanner-box"
    assert incidents[0]["severity"] == "high"


def test_additional_medium_event_is_attached_to_existing_burst_incident(client):
    payload = {
        "source": "simulator",
        "event_type": "suspicious_process",
        "severity": "medium",
        "hostname": "node-medium-attach",
        "container_name": "worker-box",
        "raw_event_json": {"process": "nc"},
    }

    for _ in range(3):
        response = client.post("/events/ingest", json=payload)
        assert response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=worker-box")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()
    assert len(incidents) == 1

    incident_id = incidents[0]["id"]

    fourth_response = client.post("/events/ingest", json=payload)
    assert fourth_response.status_code == 201

    refreshed_incidents_response = client.get("/incidents?title_contains=worker-box")
    assert refreshed_incidents_response.status_code == 200
    refreshed_incidents = refreshed_incidents_response.json()
    assert len(refreshed_incidents) == 1

    events_response = client.get(f"/incidents/{incident_id}/events")
    assert events_response.status_code == 200
    events = events_response.json()
    assert len(events) == 4

def test_port_scan_followed_by_credential_access_creates_critical_chain_incident(client):
    port_scan_payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-chain",
        "container_name": "attack-box",
        "raw_event_json": {"ports": [21, 22, 80]},
    }

    credential_payload = {
        "source": "simulator",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-chain",
        "container_name": "attack-box",
        "raw_event_json": {"file": "/etc/shadow"},
    }

    first_response = client.post("/events/ingest", json=port_scan_payload)
    second_response = client.post("/events/ingest", json=credential_payload)

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=attack-box")
    assert incidents_response.status_code == 200

    incidents = incidents_response.json()
    assert len(incidents) == 1
    assert incidents[0]["title"] == "credential_access on node-chain/attack-box"
    assert incidents[0]["severity"] == "critical"

    incident_id = incidents[0]["id"]

    linked_events_response = client.get(f"/incidents/{incident_id}/events")
    assert linked_events_response.status_code == 200
    linked_events = linked_events_response.json()

    assert len(linked_events) == 2
    assert {event["event_type"] for event in linked_events} == {
        "port_scan_detected",
        "credential_access",
    }


def test_attack_chain_outside_window_does_not_escalate_incident(client):
    port_scan_payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-chain-old",
        "container_name": "attack-box",
        "raw_event_json": {"ports": [21, 22, 80]},
    }

    credential_payload = {
        "source": "simulator",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-chain-old",
        "container_name": "attack-box",
        "raw_event_json": {"file": "/etc/shadow"},
    }

    first_response = client.post("/events/ingest", json=port_scan_payload)
    assert first_response.status_code == 201

    port_scan_event_id = first_response.json()["id"]

    with SessionLocal() as db:
        event = db.get(Event, port_scan_event_id)
        event.created_at = datetime.now(timezone.utc) - timedelta(minutes=20)
        db.commit()

    second_response = client.post("/events/ingest", json=credential_payload)
    assert second_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=attack-box")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()

    assert len(incidents) == 1
    assert incidents[0]["severity"] == "high"

    incident_id = incidents[0]["id"]

    linked_events_response = client.get(f"/incidents/{incident_id}/events")
    assert linked_events_response.status_code == 200
    linked_events = linked_events_response.json()

    assert len(linked_events) == 1
    assert linked_events[0]["event_type"] == "credential_access"


def test_attack_chain_is_source_aware(client):
    port_scan_payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-chain-source",
        "container_name": "attack-box",
        "raw_event_json": {"ports": [21, 22, 80]},
    }

    credential_payload = {
        "source": "falco",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-chain-source",
        "container_name": "attack-box",
        "raw_event_json": {"file": "/etc/shadow"},
    }

    first_response = client.post("/events/ingest", json=port_scan_payload)
    second_response = client.post("/events/ingest", json=credential_payload)

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=attack-box")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()

    assert len(incidents) == 1
    assert incidents[0]["severity"] == "high"

    incident_id = incidents[0]["id"]

    linked_events_response = client.get(f"/incidents/{incident_id}/events")
    assert linked_events_response.status_code == 200
    linked_events = linked_events_response.json()

    assert len(linked_events) == 1
    assert linked_events[0]["event_type"] == "credential_access"

def test_configurable_medium_burst_threshold_creates_incident_earlier(client, monkeypatch):
    monkeypatch.setattr(correlator, "get_medium_burst_threshold", lambda: 2)

    payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-config-burst",
        "container_name": "scanner-box",
        "raw_event_json": {"ports": [21, 22, 80]},
    }

    first_response = client.post("/events/ingest", json=payload)
    assert first_response.status_code == 201

    before_response = client.get("/incidents?title_contains=scanner-box")
    assert before_response.status_code == 200
    assert len(before_response.json()) == 0

    second_response = client.post("/events/ingest", json=payload)
    assert second_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=scanner-box")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()

    assert len(incidents) == 1
    assert incidents[0]["severity"] == "high"


def test_configurable_medium_burst_window_blocks_old_events(client, monkeypatch):
    monkeypatch.setattr(correlator, "get_medium_burst_threshold", lambda: 2)
    monkeypatch.setattr(correlator, "get_medium_burst_window_minutes", lambda: 1)

    payload = {
        "source": "simulator",
        "event_type": "suspicious_process",
        "severity": "medium",
        "hostname": "node-config-window",
        "container_name": "worker-box",
        "raw_event_json": {"process": "nc"},
    }

    first_response = client.post("/events/ingest", json=payload)
    assert first_response.status_code == 201
    first_event_id = first_response.json()["id"]

    with SessionLocal() as db:
        event = db.get(Event, first_event_id)
        event.created_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.commit()

    second_response = client.post("/events/ingest", json=payload)
    assert second_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=worker-box")
    assert incidents_response.status_code == 200
    assert len(incidents_response.json()) == 0


def test_configurable_attack_chain_window_allows_older_precursor(client, monkeypatch):
    monkeypatch.setattr(correlator, "get_attack_chain_window_minutes", lambda: 30)

    port_scan_payload = {
        "source": "simulator",
        "event_type": "port_scan_detected",
        "severity": "medium",
        "hostname": "node-config-chain",
        "container_name": "attack-box",
        "raw_event_json": {"ports": [21, 22, 80]},
    }

    credential_payload = {
        "source": "simulator",
        "event_type": "credential_access",
        "severity": "high",
        "hostname": "node-config-chain",
        "container_name": "attack-box",
        "raw_event_json": {"file": "/etc/shadow"},
    }

    first_response = client.post("/events/ingest", json=port_scan_payload)
    assert first_response.status_code == 201
    port_scan_event_id = first_response.json()["id"]

    with SessionLocal() as db:
        event = db.get(Event, port_scan_event_id)
        event.created_at = datetime.now(timezone.utc) - timedelta(minutes=20)
        db.commit()

    second_response = client.post("/events/ingest", json=credential_payload)
    assert second_response.status_code == 201

    incidents_response = client.get("/incidents?title_contains=attack-box")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()

    assert len(incidents) == 1
    assert incidents[0]["severity"] == "critical"

def test_dashboard_page_is_served(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "NetSentinel Dashboard" in response.text


def test_dashboard_css_is_served(client):
    response = client.get("/dashboard-assets/dashboard.css")
    assert response.status_code == 200
    assert "body" in response.text


def test_dashboard_js_is_served(client):
    response = client.get("/dashboard-assets/dashboard.js")
    assert response.status_code == 200
    assert "refreshDashboard" in response.text

def test_dashboard_page_contains_incident_action_button(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "toggleIncidentStatusButton" in response.text


def test_dashboard_js_contains_incident_status_update_action(client):
    response = client.get("/dashboard-assets/dashboard.js")
    assert response.status_code == 200
    assert 'method: "PATCH"' in response.text
    assert "toggleSelectedIncidentStatus" in response.text

def test_protected_endpoint_requires_api_key_when_enabled(client, monkeypatch):
    monkeypatch.setenv("NETSENTINEL_API_KEY", "test-key")

    response = client.get("/incidents")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key"


def test_protected_endpoint_accepts_api_key_when_enabled(client, monkeypatch):
    monkeypatch.setenv("NETSENTINEL_API_KEY", "test-key")

    response = client.get("/incidents", headers={"X-API-Key": "test-key"})
    assert response.status_code == 200


def test_dashboard_contains_api_key_controls(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "apiKeyInput" in response.text
    assert "saveApiKeyButton" in response.text


def test_dashboard_js_sends_api_key_header(client):
    response = client.get("/dashboard-assets/dashboard.js?v=3")
    assert response.status_code == 200
    assert "X-API-Key" in response.text
    assert "localStorage" in response.text

def test_openapi_contains_api_key_security_scheme(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200

    data = response.json()
    schemes = data["components"]["securitySchemes"]

    assert "ApiKeyAuth" in schemes
    assert schemes["ApiKeyAuth"]["type"] == "apiKey"
    assert schemes["ApiKeyAuth"]["in"] == "header"
    assert schemes["ApiKeyAuth"]["name"] == "X-API-Key"


def test_openapi_marks_incidents_endpoint_as_protected(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200

    data = response.json()
    operation = data["paths"]["/incidents"]["get"]

    assert {"ApiKeyAuth": []} in operation["security"]


def test_openapi_marks_events_endpoint_as_protected(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200

    data = response.json()
    operation = data["paths"]["/events/ingest"]["post"]

    assert {"ApiKeyAuth": []} in operation["security"]

def test_dashboard_contains_chart_panels(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "severityChart" in response.text
    assert "sourceChart" in response.text


def test_dashboard_js_contains_chart_rendering_logic(client):
    response = client.get("/dashboard-assets/dashboard.js?v=4")
    assert response.status_code == 200
    assert "renderBarChart" in response.text
    assert "renderCharts" in response.text