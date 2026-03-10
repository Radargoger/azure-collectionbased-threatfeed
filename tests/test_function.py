"""Tests for SocRadarThreatFeed.__init__ (_run function)."""

import unittest
from unittest.mock import MagicMock, call, patch


class TestRun(unittest.TestCase):
    """Tests for the _run() orchestration function."""

    ENV = {
        "SOCRADAR_API_KEY": "key",
        "SOCRADAR_COMPANY_ID": "99",
        "SOCRADAR_BASE_URL": "https://platform.socradar.com",
        "AZURE_TENANT_ID": "tid",
        "AZURE_CLIENT_ID": "cid",
        "AZURE_CLIENT_SECRET": "cs",
        "WORKSPACE_ID": "wsid",
        "INDICATOR_EXPIRATION_DAYS": "30",
    }

    def _run_with_mocks(self, collections, iocs_per_collection):
        """Execute _run() with fully mocked SOCRadar and Sentinel clients."""
        mock_socradar = MagicMock()
        mock_socradar.__enter__ = MagicMock(return_value=mock_socradar)
        mock_socradar.__exit__ = MagicMock(return_value=False)
        mock_socradar.get_collections.return_value = collections

        def iter_iocs(col_id):
            return iter(iocs_per_collection.get(col_id, []))

        mock_socradar.iter_collection_iocs.side_effect = iter_iocs

        mock_sentinel = MagicMock()
        mock_sentinel.__enter__ = MagicMock(return_value=mock_sentinel)
        mock_sentinel.__exit__ = MagicMock(return_value=False)
        mock_sentinel.upload_iocs.return_value = 5

        with patch.dict("os.environ", self.ENV):
            with patch("SocRadarThreatFeed.SocRadarClient", return_value=mock_socradar):
                with patch("SocRadarThreatFeed.SentinelTIClient", return_value=mock_sentinel):
                    from SocRadarThreatFeed import _run
                    _run()

        return mock_socradar, mock_sentinel

    def test_processes_all_collections(self):
        collections = [
            {"id": "col1", "name": "Collection One"},
            {"id": "col2", "name": "Collection Two"},
        ]
        iocs = {"col1": [{"type": "ip", "value": "1.2.3.4"}], "col2": []}
        socradar, sentinel = self._run_with_mocks(collections, iocs)
        self.assertEqual(socradar.iter_collection_iocs.call_count, 2)

    def test_skips_collection_with_no_id(self):
        collections = [{"name": "No ID collection"}]
        socradar, sentinel = self._run_with_mocks(collections, {})
        socradar.iter_collection_iocs.assert_not_called()

    def test_upload_called_for_non_empty_collection(self):
        collections = [{"id": "col1", "name": "C1"}]
        iocs = {"col1": [{"type": "ip", "value": "5.5.5.5"}]}
        _, sentinel = self._run_with_mocks(collections, iocs)
        sentinel.upload_iocs.assert_called_once()

    def test_upload_not_called_for_empty_collection(self):
        collections = [{"id": "col1", "name": "C1"}]
        iocs = {"col1": []}
        _, sentinel = self._run_with_mocks(collections, iocs)
        sentinel.upload_iocs.assert_not_called()

    def test_raises_on_missing_required_env(self):
        bad_env = {k: v for k, v in self.ENV.items() if k != "SOCRADAR_API_KEY"}
        with self.assertRaises(EnvironmentError):
            with patch.dict("os.environ", bad_env, clear=True):
                from SocRadarThreatFeed import _require_env
                _require_env("SOCRADAR_API_KEY")


if __name__ == "__main__":
    unittest.main()
