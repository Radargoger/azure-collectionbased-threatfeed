"""Tests for shared_code.socradar_client."""

import unittest
from unittest.mock import MagicMock, patch

from shared_code.socradar_client import SocRadarClient


class TestSocRadarClientInit(unittest.TestCase):
    def test_raises_on_empty_api_key(self):
        with self.assertRaises(ValueError):
            SocRadarClient(api_key="", company_id="123")

    def test_raises_on_empty_company_id(self):
        with self.assertRaises(ValueError):
            SocRadarClient(api_key="key", company_id="")

    def test_default_base_url(self):
        client = SocRadarClient(api_key="key", company_id="123")
        self.assertIn("platform.socradar.com", client._base_url)
        client.close()

    def test_custom_base_url_trailing_slash_stripped(self):
        client = SocRadarClient(api_key="key", company_id="123", base_url="https://custom.example.com/")
        self.assertEqual(client._base_url, "https://custom.example.com")
        client.close()

    def test_context_manager(self):
        with SocRadarClient(api_key="key", company_id="123") as client:
            self.assertIsNotNone(client)


class TestSocRadarClientGetCollections(unittest.TestCase):
    def _make_client(self) -> SocRadarClient:
        return SocRadarClient(api_key="testkey", company_id="99")

    def test_returns_collections_list(self):
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": [{"id": "1", "name": "TestCollection"}]}
        mock_response.raise_for_status = MagicMock()

        client._session.get = MagicMock(return_value=mock_response)
        result = client.get_collections()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "TestCollection")
        client.close()

    def test_passes_company_id_as_param(self):
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()

        client._session.get = MagicMock(return_value=mock_response)
        client.get_collections()

        _, kwargs = client._session.get.call_args
        self.assertIn("company_id", kwargs.get("params", {}))
        self.assertEqual(kwargs["params"]["company_id"], "99")
        client.close()

    def test_handles_top_level_list(self):
        """API may return a plain list instead of {'data': [...]}."""
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.json.return_value = [{"id": "2", "name": "Another"}]
        mock_response.raise_for_status = MagicMock()

        client._session.get = MagicMock(return_value=mock_response)
        result = client.get_collections()
        self.assertEqual(result[0]["id"], "2")
        client.close()

    def test_raises_on_http_error(self):
        from requests.exceptions import HTTPError

        client = self._make_client()
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = HTTPError("404")

        client._session.get = MagicMock(return_value=mock_response)

        with self.assertRaises(HTTPError):
            client.get_collections()
        client.close()


class TestSocRadarClientIterCollectionIocs(unittest.TestCase):
    def _make_client(self) -> SocRadarClient:
        return SocRadarClient(api_key="testkey", company_id="99")

    def _mock_response(self, iocs, total=None):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        payload = {"data": iocs}
        if total is not None:
            payload["total"] = total
        resp.json.return_value = payload
        return resp

    def test_yields_all_iocs_single_page(self):
        client = self._make_client()
        iocs = [{"id": str(i), "value": f"1.2.3.{i}", "type": "ip"} for i in range(3)]
        client._session.get = MagicMock(return_value=self._mock_response(iocs, total=3))

        result = list(client.iter_collection_iocs("col1"))
        self.assertEqual(len(result), 3)
        client.close()

    def test_stops_on_empty_page(self):
        client = self._make_client()
        empty_resp = self._mock_response([])
        client._session.get = MagicMock(return_value=empty_resp)

        result = list(client.iter_collection_iocs("col1"))
        self.assertEqual(result, [])
        client.close()

    def test_paginates_across_multiple_pages(self):
        client = self._make_client()
        page1 = [{"id": "1"}, {"id": "2"}]
        page2 = [{"id": "3"}, {"id": "4"}]

        resp1 = self._mock_response(page1, total=4)
        resp2 = self._mock_response(page2, total=4)
        empty = self._mock_response([])

        client._session.get = MagicMock(side_effect=[resp1, resp2, empty])

        result = list(client.iter_collection_iocs("col1", page_size=2))
        self.assertEqual(len(result), 4)
        client.close()


if __name__ == "__main__":
    unittest.main()
