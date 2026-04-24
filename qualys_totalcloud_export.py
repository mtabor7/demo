#!/usr/bin/env python3
"""
Qualys TotalCloud Report Exporter

Exports all reports, evaluations, connectors, controls, and policies from
the Qualys Total Cloud Platform via the TotalCloud REST API v1/v2.

Authentication: client-credential token flow (client ID + secret).
Docs: https://docs.qualys.com/en/tc/api/get_started/get_started.htm
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("qualys_export.log"),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLOUD_TYPES: List[str] = ["AWS", "AZURE", "GCP", "OCI"]
REPORT_FORMATS: List[str] = ["JSON", "CSV", "PDF"]

# Well-known Qualys platform gateway URLs.
# Identify your platform at: https://www.qualys.com/platform-identification
PLATFORM_URLS: Dict[str, str] = {
    "us1": "https://gateway.qg1.apps.qualys.com",
    "us2": "https://gateway.qg2.apps.qualys.com",
    "us3": "https://gateway.qg3.apps.qualys.com",
    "eu1": "https://gateway.qg1.apps.qualys.eu",
    "eu2": "https://gateway.qg2.apps.qualys.eu",
    "in1": "https://gateway.qg1.apps.qualys.in",
    "ca1": "https://gateway.qg1.apps.qualys.ca",
    "au1": "https://gateway.qg1.apps.qualys.com.au",
    "ae1": "https://gateway.qg1.apps.qualys.ae",
}

# Seconds to sleep between status-poll attempts for async reports.
_POLL_INTERVAL = 10
# Maximum poll attempts before giving up on an async report (~10 minutes).
_MAX_POLLS = 60


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class QualysAuthError(Exception):
    """Raised when API authentication fails."""


class QualysAPIError(Exception):
    """Raised when an API request fails after all retries."""


# ---------------------------------------------------------------------------
# Core exporter
# ---------------------------------------------------------------------------


class QualysTotalCloudExporter:
    """
    Authenticates with the Qualys TotalCloud API and exports all available
    report data to the local filesystem.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        output_dir: str = "qualys_reports",
        page_size: int = 100,
        max_retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.output_dir = Path(output_dir)
        self.page_size = min(max(1, page_size), 1000)  # API cap: 1–1000
        self.max_retries = max_retries

        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._session = self._build_session()

    # ------------------------------------------------------------------
    # Session / transport
    # ------------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry_cfg = Retry(
            total=self.max_retries,
            backoff_factor=2,
            # Retry on transient server errors only; 4xx are handled manually.
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_cfg)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Obtain a Bearer token via the OIDC client-credentials flow."""
        url = f"{self.base_url}/auth/oidc"
        logger.info("Authenticating against %s …", url)

        resp = self._session.post(
            url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "clientId": self.client_id,
                "clientSecret": self.client_secret,
            },
            data={
                "grant_type": "client_credentials",
                "clientId": self.client_id,
                "clientSecret": self.client_secret,
            },
            timeout=30,
        )

        if resp.status_code != 200:
            raise QualysAuthError(
                f"Authentication failed (HTTP {resp.status_code}): {resp.text[:400]}"
            )

        data = resp.json()
        self._token = data.get("access_token") or data.get("token")
        expires_in = int(data.get("expires_in", 3600))
        # Refresh 60 s before actual expiry to avoid mid-request expiration.
        self._token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)

        if not self._token:
            raise QualysAuthError("Authentication response contained no access token.")

        logger.info("Authentication successful (token valid for %d s).", expires_in)

    def _ensure_token(self) -> None:
        if not self._token or (
            self._token_expiry and datetime.now() >= self._token_expiry
        ):
            self.authenticate()

    def _auth_headers(self) -> Dict[str, str]:
        self._ensure_token()
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        payload: Optional[Dict] = None,
        stream: bool = False,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        for attempt in range(1, self.max_retries + 2):
            resp = self._session.request(
                method,
                url,
                headers=self._auth_headers(),
                params=params,
                json=payload,
                timeout=120,
                stream=stream,
            )

            if resp.status_code == 429:
                # Honour the rate-limit window advertised by the server.
                wait = int(resp.headers.get("X-RateLimit-Window-Sec", 60))
                logger.warning(
                    "Rate limit exceeded. Waiting %d s before retry %d …",
                    wait,
                    attempt,
                )
                time.sleep(wait)
                continue

            if resp.status_code == 401:
                logger.info("Token rejected (401). Re-authenticating …")
                self._token = None
                self._ensure_token()
                continue

            if resp.status_code >= 400:
                raise QualysAPIError(
                    f"{method} {path} → HTTP {resp.status_code}: {resp.text[:500]}"
                )

            return resp

        raise QualysAPIError(
            f"{method} {path} failed after {self.max_retries + 1} attempts."
        )

    def _get(
        self,
        path: str,
        params: Optional[Dict] = None,
        stream: bool = False,
    ) -> requests.Response:
        return self._request("GET", path, params=params, stream=stream)

    def _post(
        self, path: str, payload: Optional[Dict] = None
    ) -> requests.Response:
        return self._request("POST", path, payload=payload)

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------

    def _paginate(self, path: str, base_params: Optional[Dict] = None) -> List[Any]:
        """
        Iterate through all pages of a list endpoint and return every item.

        Supports two pagination styles used by the Qualys API:
          1. lastId-based:  next page fetched by passing lastId from previous response.
          2. pageNumber-based: increments 'pageNumber' query param.
        """
        params: Dict = dict(base_params or {})
        params.setdefault("pageSize", self.page_size)
        results: List[Any] = []

        while True:
            resp = self._get(path, params=params)
            data = resp.json()

            # Accept various field names used across API versions.
            page_items: List[Any] = (
                data.get("content")
                or data.get("data")
                or data.get("list")
                or data.get("evaluations")
                or data.get("resources")
                or data.get("connectors")
                or data.get("controls")
                or data.get("policies")
                or data.get("reportList")
                or []
            )
            results.extend(page_items)
            logger.debug("  %s → %d items so far.", path, len(results))

            # Determine whether more pages exist.
            has_more = data.get("hasMoreRecords") or (data.get("last") is False)
            if not has_more:
                break

            last_id = data.get("lastId")
            if last_id:
                params["lastId"] = last_id
            else:
                params["pageNumber"] = params.get("pageNumber", 0) + 1

        return results

    # ------------------------------------------------------------------
    # Assessment reports
    # ------------------------------------------------------------------

    def create_assessment_report(
        self,
        report_name: str,
        cloud_type: str,
        fmt: str = "JSON",
        policy_ids: Optional[List[str]] = None,
        connector_ids: Optional[List[str]] = None,
        tag_ids: Optional[List[str]] = None,
    ) -> Dict:
        """Trigger creation of an assessment report and return the response."""
        payload: Dict[str, Any] = {
            "reportName": report_name,
            "cloudType": cloud_type.upper(),
            "format": fmt.upper(),
        }
        if policy_ids:
            payload["policyIds"] = policy_ids
        if connector_ids:
            payload["connectorIds"] = connector_ids
        if tag_ids:
            payload["tagIds"] = tag_ids

        logger.info(
            "Creating %s assessment report for %s …", fmt.upper(), cloud_type.upper()
        )
        resp = self._post("/cloudview-api/rest/v2/report/assessment/create", payload)
        return resp.json()

    def list_assessment_reports(self) -> List[Dict]:
        """Return all assessment reports visible to this account."""
        logger.info("Listing assessment reports …")
        return self._paginate("/cloudview-api/rest/v2/report/assessment")

    def get_report_status(self, report_id: str) -> Dict:
        resp = self._get(f"/cloudview-api/rest/v2/report/assessment/{report_id}")
        return resp.json()

    def download_report(self, report_id: str, output_path: Path) -> None:
        """Stream-download a completed assessment report to *output_path*."""
        logger.info("Downloading report %s → %s …", report_id, output_path)
        resp = self._get(
            f"/cloudview-api/rest/v2/report/assessment/{report_id}/download",
            stream=True,
        )
        with open(output_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=16_384):
                fh.write(chunk)
        logger.info("Saved: %s (%d bytes)", output_path, output_path.stat().st_size)

    def _poll_and_download(
        self, report_id: str, output_path: Path
    ) -> None:
        """Poll an async report until it is ready, then download it."""
        for attempt in range(1, _MAX_POLLS + 1):
            try:
                data = self.get_report_status(report_id)
            except QualysAPIError:
                # Some report endpoints return the file directly on first GET.
                self.download_report(report_id, output_path)
                return

            status = (
                data.get("status") or data.get("reportStatus") or ""
            ).upper()

            if status in {"COMPLETED", "SUCCESS", "FINISHED", "READY", "DONE"}:
                self.download_report(report_id, output_path)
                return

            if status in {"FAILED", "ERROR", "CANCELLED"}:
                raise QualysAPIError(
                    f"Report {report_id} ended with status '{status}'."
                )

            logger.info(
                "  Report %s status: %s (poll %d/%d) …",
                report_id,
                status or "PENDING",
                attempt,
                _MAX_POLLS,
            )
            time.sleep(_POLL_INTERVAL)

        raise QualysAPIError(
            f"Report {report_id} did not complete within {_MAX_POLLS} polls."
        )

    # ------------------------------------------------------------------
    # Resource evaluations
    # ------------------------------------------------------------------

    _EVAL_PATHS: Dict[str, str] = {
        "aws": "/cloudview-api/rest/v1/aws/evaluations/resources",
        "azure": "/cloudview-api/rest/v1/azure/evaluations/resources",
        "gcp": "/cloudview-api/rest/v1/gcp/evaluations/resources",
        "oci": "/cloudview-api/rest/v1/oci/evaluations/resources",
    }

    def export_evaluations(self, cloud_type: str) -> List[Dict]:
        """Return all resource evaluation records for the given cloud provider."""
        cloud = cloud_type.lower()
        path = self._EVAL_PATHS.get(cloud)
        if not path:
            raise ValueError(
                f"Unknown cloud type '{cloud_type}'. Valid: {list(self._EVAL_PATHS)}"
            )
        logger.info("Exporting %s evaluations …", cloud_type.upper())
        results = self._paginate(path)
        logger.info("  %s: %d evaluation records.", cloud_type.upper(), len(results))
        return results

    def export_resources_by_type(
        self, resource_type: str, cloud_type: str
    ) -> List[Dict]:
        """Return v2 resources of a specific type for the given cloud."""
        path = f"/cloudview-api/rest/v2/resource/{resource_type}/{cloud_type.lower()}"
        logger.info(
            "Fetching %s/%s resources …", resource_type, cloud_type.upper()
        )
        return self._paginate(path)

    # ------------------------------------------------------------------
    # Connectors / controls / policies
    # ------------------------------------------------------------------

    def list_connectors(self, cloud_type: Optional[str] = None) -> List[Dict]:
        params: Dict = {}
        if cloud_type:
            params["cloudType"] = cloud_type.upper()
        logger.info(
            "Listing connectors%s …",
            f" for {cloud_type.upper()}" if cloud_type else "",
        )
        return self._paginate("/cloudview-api/rest/v1/connectors", params)

    def list_controls(self, cloud_type: Optional[str] = None) -> List[Dict]:
        params: Dict = {}
        if cloud_type:
            params["cloudType"] = cloud_type.upper()
        logger.info("Listing controls …")
        return self._paginate("/cloudview-api/rest/v1/controls", params)

    def list_policies(self) -> List[Dict]:
        logger.info("Listing policies …")
        return self._paginate("/cloudview-api/rest/v1/policies")

    # ------------------------------------------------------------------
    # Full export orchestration
    # ------------------------------------------------------------------

    def export_all(
        self,
        cloud_types: Optional[List[str]] = None,
        report_format: str = "JSON",
        include_assessment_reports: bool = True,
        include_evaluations: bool = True,
        include_connectors: bool = True,
        include_controls: bool = True,
        include_policies: bool = True,
    ) -> Dict:
        """
        Run a complete export of all Qualys TotalCloud data.

        Creates a timestamped sub-directory under *output_dir* containing:
          assessment_reports/   — one report file per cloud
          evaluations/          — one JSON file per cloud
          connectors.json
          controls.json
          policies.json
          export_summary.json
        """
        clouds = [c.upper() for c in (cloud_types or CLOUD_TYPES)]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.output_dir / f"export_{timestamp}"
        run_dir.mkdir(parents=True, exist_ok=True)

        summary: Dict[str, Any] = {
            "export_timestamp": timestamp,
            "base_url": self.base_url,
            "clouds": clouds,
            "files": [],
            "errors": [],
        }

        self.authenticate()

        # ---- Assessment reports ------------------------------------------
        if include_assessment_reports:
            reports_dir = run_dir / "assessment_reports"
            reports_dir.mkdir(exist_ok=True)

            for cloud in clouds:
                try:
                    report_name = f"TotalCloud_Export_{cloud}_{timestamp}"
                    result = self.create_assessment_report(
                        report_name, cloud, fmt=report_format
                    )

                    # Persist the raw creation response regardless of download.
                    meta_path = reports_dir / f"{cloud}_create_response.json"
                    _write_json(meta_path, result)
                    summary["files"].append(str(meta_path))

                    report_id = (
                        result.get("reportId")
                        or result.get("id")
                        or result.get("reportUid")
                        or result.get("uuid")
                    )
                    if report_id:
                        ext = report_format.lower()
                        dl_path = reports_dir / f"{cloud}_{report_id}.{ext}"
                        self._poll_and_download(report_id, dl_path)
                        summary["files"].append(str(dl_path))
                    else:
                        logger.warning(
                            "No report ID in creation response for %s. "
                            "See %s for details.",
                            cloud,
                            meta_path,
                        )
                except (QualysAPIError, QualysAuthError) as exc:
                    msg = f"Assessment report for {cloud}: {exc}"
                    logger.warning(msg)
                    summary["errors"].append(msg)

        # ---- Resource evaluations ----------------------------------------
        if include_evaluations:
            evals_dir = run_dir / "evaluations"
            evals_dir.mkdir(exist_ok=True)
            for cloud in clouds:
                try:
                    evals = self.export_evaluations(cloud)
                    out = evals_dir / f"{cloud}_evaluations.json"
                    _write_json(out, evals)
                    summary["files"].append(str(out))
                except (QualysAPIError, ValueError) as exc:
                    msg = f"Evaluations for {cloud}: {exc}"
                    logger.warning(msg)
                    summary["errors"].append(msg)

        # ---- Connectors ---------------------------------------------------
        if include_connectors:
            try:
                connectors = self.list_connectors()
                out = run_dir / "connectors.json"
                _write_json(out, connectors)
                summary["files"].append(str(out))
                logger.info("Saved %d connectors.", len(connectors))
            except QualysAPIError as exc:
                msg = f"Connectors: {exc}"
                logger.warning(msg)
                summary["errors"].append(msg)

        # ---- Controls -----------------------------------------------------
        if include_controls:
            try:
                controls = self.list_controls()
                out = run_dir / "controls.json"
                _write_json(out, controls)
                summary["files"].append(str(out))
                logger.info("Saved %d controls.", len(controls))
            except QualysAPIError as exc:
                msg = f"Controls: {exc}"
                logger.warning(msg)
                summary["errors"].append(msg)

        # ---- Policies -----------------------------------------------------
        if include_policies:
            try:
                policies = self.list_policies()
                out = run_dir / "policies.json"
                _write_json(out, policies)
                summary["files"].append(str(out))
                logger.info("Saved %d policies.", len(policies))
            except QualysAPIError as exc:
                msg = f"Policies: {exc}"
                logger.warning(msg)
                summary["errors"].append(msg)

        # ---- Export summary -----------------------------------------------
        summary_path = run_dir / "export_summary.json"
        _write_json(summary_path, summary)
        logger.info(
            "Export complete → %d file(s), %d error(s). Summary: %s",
            len(summary["files"]),
            len(summary["errors"]),
            summary_path,
        )
        return summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qualys_totalcloud_export",
        description="Export all reports from the Qualys Total Cloud Platform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export everything for all cloud providers (reads creds from env vars)
  QUALYS_CLIENT_ID=myid QUALYS_CLIENT_SECRET=mysecret \\
      python qualys_totalcloud_export.py --platform us1

  # Export only AWS and Azure, CSV format, to a custom directory
  python qualys_totalcloud_export.py \\
      --base-url https://gateway.qg1.apps.qualys.com \\
      --client-id myid --client-secret mysecret \\
      --clouds AWS AZURE --format CSV --output-dir ./exports

  # Skip assessment report creation, only pull evaluations + metadata
  python qualys_totalcloud_export.py --platform eu1 \\
      --client-id myid --client-secret mysecret \\
      --no-assessment-reports

  # Verbose output with debug logging
  python qualys_totalcloud_export.py --platform us1 \\
      --client-id myid --client-secret mysecret --verbose
""",
    )

    auth = parser.add_argument_group("Authentication")
    auth.add_argument(
        "--client-id",
        default=os.environ.get("QUALYS_CLIENT_ID"),
        metavar="ID",
        help="Qualys API client ID  [env: QUALYS_CLIENT_ID]",
    )
    auth.add_argument(
        "--client-secret",
        default=os.environ.get("QUALYS_CLIENT_SECRET"),
        metavar="SECRET",
        help="Qualys API client secret  [env: QUALYS_CLIENT_SECRET]",
    )

    platform = parser.add_argument_group("Platform")
    platform.add_argument(
        "--base-url",
        metavar="URL",
        help="Full Qualys gateway URL (overrides --platform). "
             "Example: https://gateway.qg1.apps.qualys.com",
    )
    platform.add_argument(
        "--platform",
        choices=list(PLATFORM_URLS),
        default="us1",
        metavar=f"{{{','.join(PLATFORM_URLS)}}}",
        help="Named platform alias (default: us1). "
             "Identify yours at https://www.qualys.com/platform-identification",
    )

    export = parser.add_argument_group("Export options")
    export.add_argument(
        "--clouds",
        nargs="+",
        default=CLOUD_TYPES,
        choices=CLOUD_TYPES,
        metavar="CLOUD",
        help=f"Cloud providers to include (default: all). Choices: {' '.join(CLOUD_TYPES)}",
    )
    export.add_argument(
        "--format",
        dest="report_format",
        default="JSON",
        choices=REPORT_FORMATS,
        help="Assessment report format (default: JSON).",
    )
    export.add_argument(
        "--output-dir",
        default="qualys_reports",
        metavar="DIR",
        help="Root output directory (default: qualys_reports/).",
    )
    export.add_argument(
        "--page-size",
        type=int,
        default=100,
        metavar="N",
        help="Records per API page, 1–1000 (default: 100).",
    )

    skip = parser.add_argument_group("Skip flags")
    skip.add_argument(
        "--no-assessment-reports",
        dest="assessment_reports",
        action="store_false",
        default=True,
        help="Skip creating / downloading assessment reports.",
    )
    skip.add_argument(
        "--no-evaluations",
        dest="evaluations",
        action="store_false",
        default=True,
        help="Skip exporting resource evaluations.",
    )
    skip.add_argument(
        "--no-connectors",
        dest="connectors",
        action="store_false",
        default=True,
        help="Skip exporting connector list.",
    )
    skip.add_argument(
        "--no-controls",
        dest="controls",
        action="store_false",
        default=True,
        help="Skip exporting controls list.",
    )
    skip.add_argument(
        "--no-policies",
        dest="policies",
        action="store_false",
        default=True,
        help="Skip exporting policies list.",
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        metavar="N",
        help="Max retry attempts for failed HTTP requests (default: 3).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.client_id:
        parser.error(
            "A client ID is required. Use --client-id or set QUALYS_CLIENT_ID."
        )
    if not args.client_secret:
        parser.error(
            "A client secret is required. Use --client-secret or set QUALYS_CLIENT_SECRET."
        )

    base_url = args.base_url or PLATFORM_URLS[args.platform]

    exporter = QualysTotalCloudExporter(
        base_url=base_url,
        client_id=args.client_id,
        client_secret=args.client_secret,
        output_dir=args.output_dir,
        page_size=args.page_size,
        max_retries=args.max_retries,
    )

    summary = exporter.export_all(
        cloud_types=args.clouds,
        report_format=args.report_format,
        include_assessment_reports=args.assessment_reports,
        include_evaluations=args.evaluations,
        include_connectors=args.connectors,
        include_controls=args.controls,
        include_policies=args.policies,
    )

    print("\n=== Qualys TotalCloud Export Summary ===")
    print(f"Timestamp : {summary['export_timestamp']}")
    print(f"Platform  : {summary['base_url']}")
    print(f"Clouds    : {', '.join(summary['clouds'])}")
    print(f"Files     : {len(summary['files'])}")
    for path in summary["files"]:
        print(f"  {path}")
    if summary["errors"]:
        print(f"\nWarnings  : {len(summary['errors'])}")
        for err in summary["errors"]:
            print(f"  [WARN] {err}")

    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
