"""
SOCRadar API client for fetching threat intelligence collections and IOCs.
"""

import logging
from typing import Any, Iterator

import requests

logger = logging.getLogger(__name__)

SOCRADAR_BASE_URL = "https://platform.socradar.com"
COLLECTIONS_ENDPOINT = "/api/threat/intelligence/socradar_collections"
COLLECTION_IOCS_ENDPOINT = "/api/threat/intelligence/socradar_collections/{collection_id}/iocs"


class SocRadarClient:
    """Client for interacting with the SOCRadar Threat Intelligence API."""

    def __init__(
        self,
        api_key: str,
        company_id: str,
        base_url: str = SOCRADAR_BASE_URL,
        timeout: int = 30,
    ) -> None:
        if not api_key:
            raise ValueError("SOCRadar API key must not be empty")
        if not company_id:
            raise ValueError("SOCRadar company ID must not be empty")

        self._company_id = company_id
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"SOCRadar {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        self._base_url = base_url.rstrip("/")

    def get_collections(self) -> list[dict[str, Any]]:
        """Return the list of available threat intelligence collections.

        Returns:
            A list of collection metadata dictionaries.

        Raises:
            requests.HTTPError: When the API returns a non-2xx response.
        """
        url = f"{self._base_url}{COLLECTIONS_ENDPOINT}"
        params = {"company_id": self._company_id}

        logger.debug("Fetching SOCRadar collections from %s", url)
        response = self._session.get(url, params=params, timeout=self._timeout)
        response.raise_for_status()

        data = response.json()
        if isinstance(data, list):
            collections = data
        else:
            collections = data.get("data", [])
        logger.info("Retrieved %d SOCRadar collections", len(collections))
        return collections

    def iter_collection_iocs(
        self, collection_id: str, page_size: int = 500
    ) -> Iterator[dict[str, Any]]:
        """Iterate over all IOCs within a collection using pagination.

        Args:
            collection_id: The identifier of the SOCRadar collection.
            page_size: Number of IOCs to request per page.

        Yields:
            Individual IOC dictionaries.

        Raises:
            requests.HTTPError: When the API returns a non-2xx response.
        """
        url = f"{self._base_url}{COLLECTION_IOCS_ENDPOINT.format(collection_id=collection_id)}"
        page = 1

        while True:
            params = {
                "company_id": self._company_id,
                "page": page,
                "page_size": page_size,
            }

            logger.debug(
                "Fetching IOCs for collection %s, page %d", collection_id, page
            )
            response = self._session.get(url, params=params, timeout=self._timeout)
            response.raise_for_status()

            data = response.json()
            if isinstance(data, list):
                iocs: list[dict[str, Any]] = data
            else:
                iocs = data.get("data", [])

            if not iocs:
                break

            for ioc in iocs:
                yield ioc

            total = data.get("total", 0)
            fetched_so_far = page * page_size
            if fetched_so_far >= total or len(iocs) < page_size:
                break

            page += 1

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self) -> "SocRadarClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
