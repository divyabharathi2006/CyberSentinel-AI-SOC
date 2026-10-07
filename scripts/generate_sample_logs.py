from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.services.demo_data import generate_events  # noqa: E402

OUTPUT = ROOT / "data" / "sample_logs" / "synthetic_events.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic synthetic defensive SOC telemetry")
    parser.add_argument("--count", type=int, default=80, help="Number of normal baseline records")
    parser.add_argument("--ingest-url", help="Optional local base URL, e.g. http://127.0.0.1:5000")
    args = parser.parse_args()
    if not 1 <= args.count <= 900:
        parser.error("--count must be between 1 and 900")
    events = generate_events(args.count)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events), encoding="utf-8")
    print(f"Wrote {len(events)} synthetic events to {OUTPUT}")
    if args.ingest_url:
        token = os.environ.get("CYBERSENTINEL_TOKEN")
        if not token:
            parser.error("Set CYBERSENTINEL_TOKEN before remote ingestion; tokens are never accepted as CLI arguments")
        response = requests.post(
            f"{args.ingest_url.rstrip('/')}/api/events",
            json=events,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if not response.ok:
            raise SystemExit(f"Ingestion failed with HTTP {response.status_code}: {response.text[:500]}")
        print(f"Ingestion response: accepted={response.json().get('accepted')}, rejected={len(response.json().get('rejected', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
