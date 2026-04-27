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