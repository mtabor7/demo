"""
Qualys Container Security - Automated Token Generation
Authenticates against the Qualys Gateway API and returns a JWT bearer token.
Supports both username/password and OIDC client credential auth methods.
"""

import os
import logging
import requests
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Base gateway URL — matches your Qualys platform region (qg1, qg2, qg3, etc.)
QUALYS_GATEWAY = os.environ.get("QUALYS_GATEWAY", "https://gateway.qg3.qualys.com")


class QualysAuthError(Exception):
    """Raised when token generation fails."""


def get_token_basic() -> str:
    """
    Obtain a JWT via username/password credentials.

    Required environment variables:
        QUALYS_USERNAME  — Qualys account username
        QUALYS_PASSWORD  — Qualys account password

    Returns:
        str: Bearer token string
    """
    username = os.environ.get("QUALYS_USERNAME")
    password = os.environ.get("QUALYS_PASSWORD")

    if not username or not password:
        raise QualysAuthError(
            "QUALYS_USERNAME and QUALYS_PASSWORD environment variables must be set."
        )

    url = f"{QUALYS_GATEWAY}/auth"
    payload = {
        "username": username,
        "password": password,
        "token": "true",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    logger.info("Requesting JWT token from %s (basic auth)", url)
    response = requests.post(url, data=payload, headers=headers, timeout=30)

    if response.status_code != 200:
        raise QualysAuthError(
            f"Token request failed: HTTP {response.status_code} — {response.text}"
        )

    token = response.text.strip()
    if not token:
        raise QualysAuthError("Received empty token from Qualys auth endpoint.")

    logger.info("JWT token obtained successfully.")
    return token


def get_token_oidc() -> str:
    """
    Obtain a JWT via OIDC client credentials (Client ID + Client Secret).
    Use this if your subscription has OIDC/OAuth 2.0 enabled.

    Required environment variables:
        QUALYS_CLIENT_ID      — OIDC client ID
        QUALYS_CLIENT_SECRET  — OIDC client secret

    Returns:
        str: Bearer token (access_token) string
    """
    client_id = os.environ.get("QUALYS_CLIENT_ID")
    client_secret = os.environ.get("QUALYS_CLIENT_SECRET")

    if not client_id or not client_secret:
        raise QualysAuthError(
            "QUALYS_CLIENT_ID and QUALYS_CLIENT_SECRET environment variables must be set."
        )

    url = f"{QUALYS_GATEWAY}/auth/oidc"
    headers = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    logger.info("Requesting JWT token from %s (OIDC)", url)
    response = requests.post(url, headers=headers, data="", timeout=30)

    if response.status_code != 200:
        raise QualysAuthError(
            f"OIDC token request failed: HTTP {response.status_code} — {response.text}"
        )

    data = response.json()
    token = data.get("access_token")
    if not token:
        raise QualysAuthError(f"No access_token in OIDC response: {data}")

    logger.info("OIDC JWT token obtained successfully.")
    return token


def get_token() -> str:
    """
    Auto-selects auth method based on available environment variables.
    Prefers OIDC if QUALYS_CLIENT_ID is set, otherwise falls back to basic auth.

    Returns:
        str: Bearer token string
    """
    if os.environ.get("QUALYS_CLIENT_ID"):
        return get_token_oidc()
    return get_token_basic()


if __name__ == "__main__":
    token = get_token()
    print(token)
