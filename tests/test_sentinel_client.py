"""Tests for shared_code.sentinel_client."""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from shared_code.sentinel_client import SentinelTIClient, _map_severity


class TestMapSeverity(unittest.TestCase):
    def test_none_returns_2(self):
        self.assertEqual(_map_severity(None), 2)

    def test_numeric_clamped(self):
        self.assertEqual(_map_severity(3), 3)
        self.assertEqual(_map_severity(-1), 0)
        self.assertEqual(_map_severity(100), 5)

    def test_string_critical(self):
        self.assertEqual(_map_severity("CRITICAL"), 5)

    def test_string_high(self):
        self.assertEqual(_map_severity("high"), 4)

    def test_string_medium(self):
        self.assertEqual(_map_severity("Medium"), 3)

    def test_string_low(self):
        self.assertEqual(_map_severity("LOW"), 2)

    def test_string_info(self):
        self.assertEqual(_map_severity("info"), 1)

    def test_unknown_string_returns_2(self):
        self.assertEqual(_map_severity("unknown_level"), 2)


class TestSentinelTIClientInit(unittest.TestCase):
    def _make_client(self, **kwargs):
        defaults = dict(
            tenant_id="tid",
            client_id="cid",
            client_secret="cs",
            workspace_id="wsid",
        )
        defaults.update(kwargs)
        with patch("shared_code.sentinel_client.msal.ConfidentialClientApplication"):
            return SentinelTIClient(**defaults)

    def test_raises_on_empty_tenant_id(self):
        with self.assertRaises(ValueError):
            with patch("shared_code.sentinel_client.msal.ConfidentialClientApplication"):
                SentinelTIClient(
                    tenant_id="",
                    client_id="cid",
                    client_secret="cs",
                    workspace_id="wsid",
                )

    def test_raises_on_empty_client_secret(self):
        with self.assertRaises(ValueError):
            with patch("shared_code.sentinel_client.msal.ConfidentialClientApplication"):
                SentinelTIClient(
                    tenant_id="tid",
                    client_id="cid",
                    client_secret="",
                    workspace_id="wsid",
                )

    def test_valid_init(self):
        client = self._make_client()
        self.assertIsNotNone(client)
        client.close()


class TestBuildIndicator(unittest.TestCase):
    def _make_client(self):
        with patch("shared_code.sentinel_client.msal.ConfidentialClientApplication"):
            return SentinelTIClient(
                tenant_id="tid",
                client_id="cid",
                client_secret="cs",
                workspace_id="wsid",
            )

    def test_ip_indicator(self):
        client = self._make_client()
        ioc = {"type": "ip", "value": "192.168.1.1", "id": "ioc1"}
        result = client._build_indicator(ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result["networkIPv4"], "192.168.1.1")
        self.assertIn("SOCRadar", result["tags"])
        client.close()

    def test_domain_indicator(self):
        client = self._make_client()
        ioc = {"type": "domain", "value": "evil.example.com"}
        result = client._build_indicator(ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result["domainName"], "evil.example.com")
        client.close()

    def test_url_indicator(self):
        client = self._make_client()
        ioc = {"type": "url", "value": "http://evil.example.com/payload"}
        result = client._build_indicator(ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result["url"], "http://evil.example.com/payload")
        client.close()

    def test_sha256_indicator(self):
        client = self._make_client()
        ioc = {
            "type": "sha256",
            "value": "a" * 64,
            "id": "hash1",
        }
        result = client._build_indicator(ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result["fileHashValue"], "a" * 64)
        self.assertEqual(result["fileHashType"], "sha256")
        client.close()

    def test_unsupported_type_returns_none(self):
        client = self._make_client()
        ioc = {"type": "certificate", "value": "some_cert"}
        result = client._build_indicator(ioc)
        self.assertIsNone(result)
        client.close()

    def test_empty_value_returns_none(self):
        client = self._make_client()
        ioc = {"type": "ip", "value": ""}
        result = client._build_indicator(ioc)
        self.assertIsNone(result)
        client.close()

    def test_expiration_is_future(self):
        client = self._make_client()
        ioc = {"type": "ip", "value": "10.0.0.1"}
        result = client._build_indicator(ioc)
        expiry = datetime.strptime(result["expirationDateTime"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        self.assertGreater(expiry, datetime.now(timezone.utc))
        client.close()

    def test_confidence_defaults_to_75(self):
        client = self._make_client()
        ioc = {"type": "ip", "value": "10.0.0.2"}
        result = client._build_indicator(ioc)
        self.assertEqual(result["confidence"], 75)
        client.close()

    def test_ioc_type_and_value_alternate_field_names(self):
        """SOCRadar may use ioc_type / ioc_value keys."""
        client = self._make_client()
        ioc = {"ioc_type": "domain", "ioc_value": "alt.example.com"}
        result = client._build_indicator(ioc)
        self.assertIsNotNone(result)
        self.assertEqual(result["domainName"], "alt.example.com")
        client.close()


class TestUploadIocs(unittest.TestCase):
    def _make_client(self):
        with patch("shared_code.sentinel_client.msal.ConfidentialClientApplication") as mock_msal:
            client = SentinelTIClient(
                tenant_id="tid",
                client_id="cid",
                client_secret="cs",
                workspace_id="wsid",
            )
            client._msal_app = MagicMock()
            client._msal_app.acquire_token_silent.return_value = None
            client._msal_app.acquire_token_for_client.return_value = {
                "access_token": "fake-token"
            }
            return client

    def test_returns_zero_for_empty_ioc_list(self):
        client = self._make_client()
        result = client.upload_iocs([])
        self.assertEqual(result, 0)
        client.close()

    def test_returns_zero_when_all_iocs_unsupported(self):
        client = self._make_client()
        result = client.upload_iocs([{"type": "certificate", "value": "x"}])
        self.assertEqual(result, 0)
        client.close()

    def test_submits_in_batches(self):
        client = self._make_client()

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"value": [{}] * 10}
        client._session.post = MagicMock(return_value=mock_response)

        iocs = [{"type": "ip", "value": f"1.2.3.{i}"} for i in range(10)]
        result = client.upload_iocs(iocs)
        self.assertEqual(result, 10)
        self.assertEqual(client._session.post.call_count, 1)
        client.close()

    def test_batches_at_max_batch_size(self):
        from shared_code.sentinel_client import MAX_BATCH_SIZE

        client = self._make_client()

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"value": [{}] * MAX_BATCH_SIZE}
        client._session.post = MagicMock(return_value=mock_response)

        iocs = [{"type": "ip", "value": f"10.0.{i // 256}.{i % 256}"} for i in range(MAX_BATCH_SIZE + 1)]
        client.upload_iocs(iocs)
        self.assertEqual(client._session.post.call_count, 2)
        client.close()


if __name__ == "__main__":
    unittest.main()
