# azure-collectionbased-threatfeed

Azure Function App that automatically fetches threat intelligence collections
from [SOCRadar](https://socradar.io) and uploads the resulting IOC indicators
to [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/overview)
via the Graph API tiIndicators endpoint.

## Architecture

```
SOCRadar API
  └─► SocRadarThreatFeed (Azure Function – timer)
        ├─ shared_code/socradar_client.py  ← fetch collections + IOCs
        └─ shared_code/sentinel_client.py  ← upload indicators to Sentinel
```

The function runs on a configurable CRON schedule (default: top of every hour),
pages through every collection, converts each IOC to a Sentinel `tiIndicator`
object, and submits them in batches of up to 100.

### Supported IOC types

| SOCRadar type | Sentinel field      |
|---------------|---------------------|
| `ip` / `ipv4` | `networkIPv4`       |
| `ipv6`        | `networkIPv6`       |
| `domain` / `hostname` | `domainName` |
| `url`         | `url`               |
| `md5`         | `fileHashValue` (md5) |
| `sha1`        | `fileHashValue` (sha1) |
| `sha256`      | `fileHashValue` (sha256) |
| `email`       | `emailSenderAddress` |

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Azure subscription with Microsoft Sentinel | |
| Log Analytics workspace | Where Sentinel is configured |
| SOCRadar account | API key + company ID |
| Azure AD app registration | With `ThreatIndicators.ReadWrite.OwnedBy` permission on the Microsoft Graph API |
| Python 3.10+ | For local development / testing |
| Azure Functions Core Tools v4 | For local testing |

---

## Getting started

### 1 — Clone and install dependencies

```bash
git clone https://github.com/Radargoger/azure-collectionbased-threatfeed.git
cd azure-collectionbased-threatfeed
pip install -r requirements.txt
```

### 2 — Configure environment variables

Copy the template and fill in your own values:

```bash
cp local.settings.json.template local.settings.json
```

| Variable | Description |
|----------|-------------|
| `SOCRADAR_API_KEY` | SOCRadar API key |
| `SOCRADAR_COMPANY_ID` | SOCRadar company / organisation ID |
| `SOCRADAR_BASE_URL` | SOCRadar platform base URL (default: `https://platform.socradar.com`) |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Azure AD application (client) ID |
| `AZURE_CLIENT_SECRET` | Azure AD application client secret |
| `WORKSPACE_ID` | Log Analytics workspace ID |
| `INDICATOR_EXPIRATION_DAYS` | Days before uploaded indicators expire (default: `30`) |
| `TIMER_SCHEDULE` | Azure CRON expression (default: `0 0 * * * *` = top of every hour) |

### 3 — Create the Azure AD app registration

1. Go to **Azure Active Directory → App registrations → New registration**.
2. Note the **Application (client) ID** and **Tenant ID**.
3. Under **Certificates & secrets**, create a **New client secret** and note its value.
4. Under **API permissions**, add:
   - `Microsoft Graph` → `ThreatIndicators.ReadWrite.OwnedBy` (Application permission)
5. Click **Grant admin consent**.

### 4 — Deploy to Azure

```bash
# Create a Function App (Python, Consumption plan)
az functionapp create \
  --resource-group <YOUR_RG> \
  --consumption-plan-location <LOCATION> \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name <YOUR_FUNC_APP_NAME> \
  --storage-account <YOUR_STORAGE_ACCOUNT>

# Set application settings
az functionapp config appsettings set \
  --name <YOUR_FUNC_APP_NAME> \
  --resource-group <YOUR_RG> \
  --settings \
    SOCRADAR_API_KEY="<key>" \
    SOCRADAR_COMPANY_ID="<id>" \
    AZURE_TENANT_ID="<tid>" \
    AZURE_CLIENT_ID="<cid>" \
    AZURE_CLIENT_SECRET="<secret>" \
    WORKSPACE_ID="<wsid>"

# Deploy the code
func azure functionapp publish <YOUR_FUNC_APP_NAME>
```

---

## Running tests

```bash
pip install -r requirements.txt pytest
python -m pytest tests/ -v
```

---

## Querying indicators in Sentinel

After the first successful run, use KQL in **Microsoft Sentinel → Logs**:

```kql
// All threat indicators ingested from SOCRadar
ThreatIntelligenceIndicator
| where Tags has "SOCRadar"
| project TimeGenerated, IndicatorId, NetworkIP, DomainName, Url, FileHashValue, ThreatType, ConfidenceScore, ExpirationDateTime
| sort by TimeGenerated desc
```

---

## Troubleshooting

**No indicators appear in Sentinel**
- Wait up to 15 minutes for the first ingestion to propagate.
- Check the Function App logs in the Azure Portal under **Monitor → Logs**.
- Verify `AZURE_CLIENT_ID` has the `ThreatIndicators.ReadWrite.OwnedBy` permission with admin consent granted.

**Authentication errors**
- Confirm `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` are correct.
- Ensure the client secret has not expired.

**SOCRadar API errors**
- Verify `SOCRADAR_API_KEY` and `SOCRADAR_COMPANY_ID` are valid.
- Check your SOCRadar subscription includes API access to threat intelligence collections.

---

## Support

- SOCRadar: [support@socradar.io](mailto:support@socradar.io)
- Issues: [GitHub Issues](https://github.com/Radargoger/azure-collectionbased-threatfeed/issues)
