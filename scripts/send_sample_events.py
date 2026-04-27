import json
import sys
from pathlib import Path
from urllib import request


DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_EVENTS_FILE = Path("lab/sample_events/falco_samples.json")


def post_event(base_url: str, payload: dict) -> tuple[int, str]:
    url = f"{base_url.rstrip('/')}/events/ingest"
    data = json.dumps(payload).encode("utf-8")

    req = request.Request(
        url=url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with request.urlopen(req) as response:
        body = response.read().decode("utf-8")
        return response.status, body


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE_URL

    if not DEFAULT_EVENTS_FILE.exists():
        print(f"Events file not found: {DEFAULT_EVENTS_FILE}")
        return 1

    events = json.loads(DEFAULT_EVENTS_FILE.read_text(encoding="utf-8"))

    print(f"Sending {len(events)} events to {base_url}...")

    for index, event in enumerate(events, start=1):
        status_code, body = post_event(base_url, event)
        print(f"[{index}] status={status_code} event_type={event['event_type']}")
        print(body)

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())