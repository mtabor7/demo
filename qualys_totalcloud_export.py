#!/usr/bin/env python3
"""
Export on-screen reports from Qualys TotalCloud via REST API.

Supports exporting: findings, resources, evaluations, and controls.
Output formats: CSV or JSON.

Usage:
    python qualys_totalcloud_export.py --report findings --format csv
    python qualys_totalcloud_export.py --report resources --format json --cloud AWS
    python qualys_totalcloud_export.py --report evaluations --output results.csv

Credentials are loaded from environment variables (see .env.example).
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

import requests
from dotenv import load_dotenv

load_dotenv()

PLATFORM_URLS = {
    "US1": "https://qualysapi.qualys.com",
    "US2": "https://qualysapi.qg2.apps.qualys.com",
    "US3": "https://qualysapi.qg3.apps.qualys.com",
    "EU1": "https://qualysapi.qualys.eu",
    "EU2": "https://qualysapi.qg2.apps.qualys.eu",
    "IN1": "https://qualysapi.qg1.apps.qualys.in",
    "CA1": "https://qualysapi.qg1.apps.qualys.ca",
    "AE1": "https://qualysapi.qg1.apps.qualys.ae",
    "AU1": "https://qualysapi.qg1.apps.qualys.com.au",
}

REPORT_TYPES = ["findings", "resources", "evaluations", "controls"]

PAGE_SIZE = 100
MAX_RETRIES = 3
RETRY_DELAY = 2


class QualysTotalCloudClient:
    def __init__(self, username: str, password: str, platform_url: str):
        self.base_url = f"{platform_url.rstrip('/')}/cloudview-api/rest/v1"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def _get(self, endpoint: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.get(url, params=params, timeout=60)
                resp.raise_for_status()
                return resp.json()
            except requests.HTTPError as e:
                if e.response.status_code == 401:
                    print("ERROR: Authentication failed. Check your credentials.", file=sys.stderr)
                    sys.exit(1)
                if e.response.status_code == 429 or e.response.status_code >= 500:
                    if attempt < MAX_RETRIES:
                        wait = RETRY_DELAY * attempt
                        print(f"  Request failed ({e.response.status_code}), retrying in {wait}s...", file=sys.stderr)
                        time.sleep(wait)
                        continue
                raise
            except requests.ConnectionError as e:
                if attempt < MAX_RETRIES:
                    wait = RETRY_DELAY * attempt
                    print(f"  Connection error, retrying in {wait}s...", file=sys.stderr)
                    time.sleep(wait)
                    continue
                raise
        raise RuntimeError(f"Request to {url} failed after {MAX_RETRIES} attempts")

    def _paginate(self, endpoint: str, params: dict | None = None) -> Iterator[dict]:
        """Yield every record across all pages."""
        params = dict(params or {})
        params["pageSize"] = PAGE_SIZE
        page = 0
        total_pages = None

        while True:
            params["pageNo"] = page
            data = self._get(endpoint, params)

            # TotalCloud wraps results in a standard Spring Page envelope
            records = data.get("content", data if isinstance(data, list) else [])
            yield from records

            if total_pages is None:
                total_pages = data.get("totalPages", 1)
            page += 1
            if page >= total_pages:
                break

    # ---------- Report-specific fetchers ----------

    def get_findings(self, cloud_provider: str | None = None,
                     severity: str | None = None,
                     filter_expr: str | None = None) -> Iterator[dict]:
        params: dict[str, Any] = {}
        if cloud_provider:
            params["cloudType"] = cloud_provider.upper()
        if severity:
            params["severity"] = severity.upper()
        if filter_expr:
            params["filter"] = filter_expr
        yield from self._paginate("findings", params)

    def get_resources(self, cloud_provider: str | None = None,
                      resource_type: str | None = None,
                      filter_expr: str | None = None) -> Iterator[dict]:
        params: dict[str, Any] = {}
        if cloud_provider:
            params["cloudType"] = cloud_provider.upper()
        if resource_type:
            params["resourceType"] = resource_type
        if filter_expr:
            params["filter"] = filter_expr
        yield from self._paginate("resources", params)

    def get_evaluations(self, cloud_provider: str | None = None,
                        filter_expr: str | None = None) -> Iterator[dict]:
        params: dict[str, Any] = {}
        if cloud_provider:
            params["cloudType"] = cloud_provider.upper()
        if filter_expr:
            params["filter"] = filter_expr
        yield from self._paginate("evaluations", params)

    def get_controls(self, cloud_provider: str | None = None,
                     filter_expr: str | None = None) -> Iterator[dict]:
        params: dict[str, Any] = {}
        if cloud_provider:
            params["cloudType"] = cloud_provider.upper()
        if filter_expr:
            params["filter"] = filter_expr
        yield from self._paginate("controls", params)


# ---------- Export helpers ----------

def flatten(record: dict, prefix: str = "") -> dict:
    """Flatten nested dicts for CSV output."""
    out: dict = {}
    for k, v in record.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(flatten(v, key))
        elif isinstance(v, list):
            out[key] = json.dumps(v)
        else:
            out[key] = v
    return out


def export_json(records: list[dict], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)
    print(f"Exported {len(records)} records to {output_path}")


def export_csv(records: list[dict], output_path: str) -> None:
    if not records:
        print("No records to export.")
        return

    flat = [flatten(r) for r in records]
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in flat:
        for k in row:
            if k not in seen:
                fieldnames.append(k)
                seen.add(k)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat)

    print(f"Exported {len(flat)} records to {output_path}")


# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Export on-screen reports from Qualys TotalCloud",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--report", choices=REPORT_TYPES, default="findings",
        help="Report type to export (default: findings)",
    )
    p.add_argument(
        "--format", choices=["csv", "json"], default="csv",
        help="Output file format (default: csv)",
    )
    p.add_argument(
        "--output", default=None,
        help="Output file path (default: <report>_<timestamp>.<format>)",
    )
    p.add_argument(
        "--cloud", default=None,
        help="Cloud provider filter: AWS | AZURE | GCP",
    )
    p.add_argument(
        "--severity", default=None,
        help="Severity filter for findings: CRITICAL | HIGH | MEDIUM | LOW | INFO",
    )
    p.add_argument(
        "--resource-type", default=None,
        help="Resource type filter for resources report (e.g. AWS_EC2_INSTANCE)",
    )
    p.add_argument(
        "--filter", dest="filter_expr", default=None,
        help="Qualys filter expression (e.g. 'region:us-east-1')",
    )
    p.add_argument(
        "--platform", default=None,
        help=(
            f"Platform key ({', '.join(PLATFORM_URLS)}) or full base URL. "
            "Overrides QUALYS_PLATFORM env var."
        ),
    )
    return p


def resolve_platform(platform_arg: str | None) -> str:
    raw = platform_arg or os.getenv("QUALYS_PLATFORM", "US1")
    return PLATFORM_URLS.get(raw.upper(), raw)


def default_output_path(report: str, fmt: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{report}_{ts}.{fmt}"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    username = os.getenv("QUALYS_USERNAME")
    password = os.getenv("QUALYS_PASSWORD")

    if not username or not password:
        print(
            "ERROR: QUALYS_USERNAME and QUALYS_PASSWORD must be set "
            "(via environment variables or a .env file).",
            file=sys.stderr,
        )
        sys.exit(1)

    platform_url = resolve_platform(args.platform)
    output_path = args.output or default_output_path(args.report, args.format)

    print(f"Connecting to {platform_url}")
    client = QualysTotalCloudClient(username, password, platform_url)

    print(f"Fetching {args.report}...")
    if args.report == "findings":
        records = list(client.get_findings(args.cloud, args.severity, args.filter_expr))
    elif args.report == "resources":
        records = list(client.get_resources(args.cloud, args.resource_type, args.filter_expr))
    elif args.report == "evaluations":
        records = list(client.get_evaluations(args.cloud, args.filter_expr))
    elif args.report == "controls":
        records = list(client.get_controls(args.cloud, args.filter_expr))
    else:
        print(f"Unknown report type: {args.report}", file=sys.stderr)
        sys.exit(1)

    print(f"Retrieved {len(records)} records.")

    if args.format == "json":
        export_json(records, output_path)
    else:
        export_csv(records, output_path)


if __name__ == "__main__":
    main()
