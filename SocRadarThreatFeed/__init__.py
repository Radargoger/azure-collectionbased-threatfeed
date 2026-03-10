"""
SocRadarThreatFeed – Azure Function (timer trigger).

Fetches threat intelligence IOCs from SOCRadar collections and uploads them
to Microsoft Sentinel via the Graph tiIndicators API.

Required application settings
──────────────────────────────
SOCRADAR_API_KEY          SOCRadar API key
SOCRADAR_COMPANY_ID       SOCRadar company (organisation) ID
SOCRADAR_BASE_URL         SOCRadar platform base URL (optional, defaults to
                          https://platform.socradar.com)
AZURE_TENANT_ID           Azure AD tenant ID for Sentinel authentication
AZURE_CLIENT_ID           Azure AD application (client) ID
AZURE_CLIENT_SECRET       Azure AD application client secret
WORKSPACE_ID              Log Analytics workspace ID (used as a tag)
INDICATOR_EXPIRATION_DAYS Number of days before uploaded indicators expire
                          (optional, default 30)
TIMER_SCHEDULE            Azure cron expression controlling the run schedule
                          (optional, default: top of every hour)
"""

import logging
import os
from typing import Any

import azure.functions as func

from shared_code.sentinel_client import SentinelTIClient
from shared_code.socradar_client import SocRadarClient

logger = logging.getLogger(__name__)


def _require_env(name: str) -> str:
    """Return the value of a required environment variable.

    Raises:
        EnvironmentError: When the variable is not set or is empty.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set or is empty."
        )
    return value


def main(timer: func.TimerRequest) -> None:  # pragma: no cover – entry point
    """Entry point called by the Azure Functions runtime."""
    if timer.past_due:
        logger.warning("Timer trigger is running late (past due)")

    try:
        _run()
    except Exception:
        logger.exception("Unhandled error in SocRadarThreatFeed function")
        raise


def _run() -> None:
    """Core logic: fetch SOCRadar IOCs and upload to Sentinel."""
    socradar_api_key = _require_env("SOCRADAR_API_KEY")
    socradar_company_id = _require_env("SOCRADAR_COMPANY_ID")
    socradar_base_url = os.environ.get(
        "SOCRADAR_BASE_URL", "https://platform.socradar.com"
    )

    azure_tenant_id = _require_env("AZURE_TENANT_ID")
    azure_client_id = _require_env("AZURE_CLIENT_ID")
    azure_client_secret = _require_env("AZURE_CLIENT_SECRET")
    workspace_id = _require_env("WORKSPACE_ID")

    expiration_days = int(os.environ.get("INDICATOR_EXPIRATION_DAYS", "30"))

    total_submitted = 0

    with SocRadarClient(
        api_key=socradar_api_key,
        company_id=socradar_company_id,
        base_url=socradar_base_url,
    ) as socradar, SentinelTIClient(
        tenant_id=azure_tenant_id,
        client_id=azure_client_id,
        client_secret=azure_client_secret,
        workspace_id=workspace_id,
        expiration_days=expiration_days,
    ) as sentinel:
        collections = socradar.get_collections()
        logger.info("Processing %d SOCRadar collection(s)", len(collections))

        for collection in collections:
            collection_id = str(
                collection.get("id") or collection.get("collection_id") or ""
            )
            collection_name = collection.get("name", collection_id)

            if not collection_id:
                logger.warning("Skipping collection with missing ID: %s", collection)
                continue

            logger.info("Fetching IOCs from collection '%s' (%s)", collection_name, collection_id)
            iocs: list[dict[str, Any]] = list(socradar.iter_collection_iocs(collection_id))

            if not iocs:
                logger.info("Collection '%s' is empty", collection_name)
                continue

            logger.info(
                "Uploading %d IOC(s) from collection '%s' to Sentinel",
                len(iocs),
                collection_name,
            )
            submitted = sentinel.upload_iocs(iocs)
            total_submitted += submitted

    logger.info("SocRadarThreatFeed completed: %d indicator(s) submitted", total_submitted)
