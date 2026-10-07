from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the CyberSentinel HTTP health endpoint")
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/health")
    args = parser.parse_args()
    try:
        with urlopen(Request(args.url, headers={"Accept": "application/json"}), timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            print(json.dumps(payload, indent=2))
            return 0 if payload.get("success") else 1
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        print(f"Health check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
