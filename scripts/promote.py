"""Operator runbook wrapper for promoting a Mosaic Database standby."""

import argparse
import json
import sys
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database_id")
    parser.add_argument("host_id")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-key", required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    request = Request(
        f"{args.url.rstrip('/')}/v1/admin/databases/{args.database_id}/promote",
        data=json.dumps({"host_id": args.host_id, "force": args.force}).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Admin-Key": args.admin_key,
        },
        method="POST",
    )
    with urlopen(request) as response:
        sys.stdout.write(response.read().decode() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
