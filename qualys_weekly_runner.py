"""
Qualys Container Security — Weekly Automated Runner
Runs every Monday via cron (or directly).  Generates a fresh JWT token,
then calls your existing Qualys CS script with that token injected.

Cron entry (runs at 08:00 every Monday):
    0 8 * * 1 /path/to/venv/bin/python /path/to/qualys_weekly_runner.py >> /var/log/qualys_runner.log 2>&1

Usage:
    python qualys_weekly_runner.py            # run immediately
    python qualys_weekly_runner.py --force    # skip Monday-only guard
"""

import os
import sys
import logging
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from qualys_auth import get_token, QualysAuthError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — override via environment variables if needed
# ---------------------------------------------------------------------------

# Absolute path to your existing Qualys CS script
QUALYS_SCRIPT = os.environ.get(
    "QUALYS_SCRIPT_PATH",
    str(Path(__file__).parent / "qualys_cs_script.py"),
)

# Python interpreter to use when calling the script
PYTHON_BIN = os.environ.get("QUALYS_PYTHON_BIN", sys.executable)

# Base gateway URL (used by your script if it needs it)
QUALYS_GATEWAY = os.environ.get("QUALYS_GATEWAY", "https://gateway.qg3.qualys.com")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_monday() -> bool:
    return datetime.now(timezone.utc).weekday() == 0  # 0 = Monday


def run_qualys_script(token: str) -> int:
    """
    Invokes the existing Qualys CS script as a subprocess with the token
    injected via the QUALYS_TOKEN environment variable.

    Returns the process exit code.
    """
    script_path = Path(QUALYS_SCRIPT)
    if not script_path.exists():
        logger.error("Qualys script not found at: %s", script_path)
        return 1

    env = os.environ.copy()
    env["QUALYS_TOKEN"] = token          # token available to the child script
    env["QUALYS_GATEWAY"] = QUALYS_GATEWAY

    logger.info("Launching script: %s", script_path)
    result = subprocess.run(
        [PYTHON_BIN, str(script_path)],
        env=env,
        check=False,
    )
    logger.info("Script exited with code %d", result.returncode)
    return result.returncode


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Qualys CS weekly automated runner")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run regardless of day of week (skips Monday-only guard)",
    )
    args = parser.parse_args()

    if not args.force and not is_monday():
        logger.info(
            "Today is not Monday (%s). Use --force to run anyway. Exiting.",
            datetime.now(timezone.utc).strftime("%A"),
        )
        return 0

    logger.info("=== Qualys CS Weekly Run — %s ===", datetime.now(timezone.utc).isoformat())

    # Step 1: Obtain JWT token (no user input required)
    try:
        token = get_token()
    except QualysAuthError as exc:
        logger.error("Authentication failed: %s", exc)
        return 1

    # Step 2: Pass token to your existing script
    return run_qualys_script(token)


if __name__ == "__main__":
    sys.exit(main())
