"""
Microsoft Sentinel Threat Intelligence client.

Uploads threat indicators to Microsoft Sentinel via the Microsoft Graph
tiIndicators API (beta), authenticating with Azure AD using the client
credentials flow.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import msal
import requests

logger = logging.getLogger(__name__)

GRAPH_AUTHORITY = "https://login.microsoftonline.com/{tenant_id}"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
TIINDICATORS_ENDPOINT = "https://graph.microsoft.com/beta/security/tiIndicators"
TIINDICATORS_SUBMIT_ENDPOINT = (
    "https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators"
)
MAX_BATCH_SIZE = 100

# Mapping from SOCRadar IOC types to Sentinel threat indicator fields
IOC_TYPE_MAP = {
    "ip": "networkIPv4",
    "ipv4": "networkIPv4",
    "ipv6": "networkIPv6",
    "domain": "domainName",
    "hostname": "domainName",
    "url": "url",
    "md5": "fileHashValue",
    "sha1": "fileHashValue",
    "sha256": "fileHashValue",
    "email": "emailSenderAddress",
}

HASH_TYPE_MAP = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}


class SentinelTIClient:
    """Client for uploading threat indicators to Microsoft Sentinel."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        workspace_id: str,
        expiration_days: int = 30,
        timeout: int = 30,
    ) -> None:
        for name, value in [
            ("tenant_id", tenant_id),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("workspace_id", workspace_id),
        ]:
            if not value:
                raise ValueError(f"{name} must not be empty")

        self._workspace_id = workspace_id
        self._expiration_days = expiration_days
        self._timeout = timeout
        self._session = requests.Session()

        self._msal_app = msal.ConfidentialClientApplication(
            client_id=client_id,
            authority=GRAPH_AUTHORITY.format(tenant_id=tenant_id),
            client_credential=client_secret,
        )

    def _get_access_token(self) -> str:
        """Acquire an OAuth2 access token via the client credentials flow."""
        result = self._msal_app.acquire_token_silent(GRAPH_SCOPE, account=None)
        if not result:
            result = self._msal_app.acquire_token_for_client(scopes=GRAPH_SCOPE)

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            raise RuntimeError(f"Failed to acquire access token: {error}")

        return result["access_token"]

    def _build_indicator(self, ioc: dict[str, Any]) -> dict[str, Any] | None:
        """Convert a SOCRadar IOC dict to a Sentinel tiIndicator payload.

        Returns None if the IOC type is not supported.
        """
        ioc_type = (ioc.get("type") or ioc.get("ioc_type") or "").lower()
        ioc_value = ioc.get("value") or ioc.get("ioc_value") or ioc.get("indicator", "")

        sentinel_field = IOC_TYPE_MAP.get(ioc_type)
        if not sentinel_field or not ioc_value:
            logger.debug("Skipping unsupported IOC type '%s' or empty value", ioc_type)
            return None

        expiration = datetime.now(timezone.utc) + timedelta(days=self._expiration_days)

        indicator: dict[str, Any] = {
            "action": "alert",
            "confidence": int(ioc.get("confidence", 75)),
            "description": ioc.get("description") or "SOCRadar Threat Intelligence",
            "expirationDateTime": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "externalId": str(ioc.get("id") or ioc.get("ioc_id") or ioc_value),
            "severity": _map_severity(ioc.get("risk_level") or ioc.get("severity")),
            "tags": ["SOCRadar"] + list(ioc.get("tags") or []),
            "targetProduct": "Azure Sentinel",
            "threatType": ioc.get("threat_type") or "WatchList",
            "tlpLevel": (ioc.get("tlp") or "white").lower(),
        }

        if sentinel_field == "fileHashValue":
            indicator["fileHashType"] = HASH_TYPE_MAP.get(ioc_type, ioc_type)

        indicator[sentinel_field] = ioc_value
        return indicator

    def upload_iocs(self, iocs: list[dict[str, Any]]) -> int:
        """Build and upload indicators to Sentinel in batches.

        Args:
            iocs: List of SOCRadar IOC dicts.

        Returns:
            The total number of successfully submitted indicators.
        """
        indicators = []
        for ioc in iocs:
            built = self._build_indicator(ioc)
            if built:
                indicators.append(built)

        if not indicators:
            logger.info("No valid indicators to upload")
            return 0

        token = self._get_access_token()
        self._session.headers.update({"Authorization": f"Bearer {token}"})

        submitted = 0
        for batch_start in range(0, len(indicators), MAX_BATCH_SIZE):
            batch = indicators[batch_start : batch_start + MAX_BATCH_SIZE]
            submitted += self._submit_batch(batch)

        logger.info("Submitted %d indicators to Microsoft Sentinel", submitted)
        return submitted

    def _submit_batch(self, batch: list[dict[str, Any]]) -> int:
        """POST a single batch of indicators to the Graph API.

        Returns:
            The number of indicators accepted by the API.
        """
        payload = {"value": batch}
        response = self._session.post(
            TIINDICATORS_SUBMIT_ENDPOINT,
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        result = response.json()
        accepted = len(result.get("value", batch))
        logger.debug("Batch of %d indicators accepted (%d returned)", len(batch), accepted)
        return accepted

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self) -> "SentinelTIClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _map_severity(risk_level: Any) -> int:
    """Convert a SOCRadar risk level label or numeric score to a 0–5 integer."""
    if risk_level is None:
        return 2

    if isinstance(risk_level, (int, float)):
        return max(0, min(5, int(risk_level)))

    mapping = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
    }
    return mapping.get(str(risk_level).lower(), 2)
