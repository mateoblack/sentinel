# Device Posture Verification Guide

Sentinel device posture verification ensures credentials are only issued to devices meeting security requirements, with MDM integration for server-side verification.

## Overview

Device posture verification adds a layer of endpoint security to credential issuance. Before issuing credentials, Sentinel verifies that the requesting device meets security requirements defined in policy:

- MDM enrollment status
- Disk encryption enabled
- Firewall enabled
- Minimum OS version
- Allowed OS types

**Use cases:**

| Use Case | Policy Condition | Description |
|----------|------------------|-------------|
| MDM enrollment required | `require_mdm: true` | Only managed devices can access credentials |
| Disk encryption required | `require_encryption: true` | Protect against device theft/loss |
| Minimum OS version | `min_os_version: "14.0.0"` | Ensure security patches are applied |
| Compliance required | `require_mdm_compliant: true` | Device passes MDM compliance checks |
| OS type restriction | `allowed_os_types: [darwin]` | Restrict to specific platforms |

## Threat Model

Device posture verification prevents credential access from unmanaged or compromised devices.

### Attacks Prevented

| Attack | Description | How Device Posture Prevents It |
|--------|-------------|--------------------------------|
| Stolen credentials on unmanaged device | Attacker obtains valid SSO credentials but uses them from personal laptop | `require_mdm: true` rejects devices not enrolled in MDM |
| Credential exfiltration from compromised device | Malware on unencrypted device extracts credentials | `require_encryption: true` ensures disk encryption, reducing exfiltration risk |
| Insider access from personal device | Employee uses personal device to access production | MDM enrollment check ensures only corporate devices access sensitive profiles |
| Outdated OS with known vulnerabilities | Attacker exploits unpatched OS to steal credentials | `min_os_version` ensures security patches are applied |

### Trust Model

```
+----------------+     +------------------+     +-------------------+
|    Device      |---->|  Lambda TVM      |---->|   MDM Provider    |
|  (Sentinel     |     | (Credential      |     |   (Jamf Pro,      |
|   Client)      |     |  Server)         |     |    Intune, etc.)  |
+----------------+     +------------------+     +-------------------+
        |                      |                        |
        |                      |                        |
        v                      v                        v
  Device ID             Query device by          Return enrollment,
  (HMAC-SHA256          extension attribute      compliance, posture
   of machine ID)       SentinelDeviceID         status

                               |
                               v
                    +--------------------+
                    |  Policy Evaluation |
                    |  (device conditions|
                    |   + user/profile)  |
                    +--------------------+
                               |
                               v
                    +--------------------+
                    |    Credentials     |
                    |   (if all pass)    |
                    +--------------------+
```

**Key trust assumptions:**

1. **Device ID integrity:** The device ID is computed locally using HMAC-SHA256 of the machine ID. A compromised device could spoof this, but MDM enrollment verification provides the real security boundary.

2. **MDM as source of truth:** The MDM provider (Jamf Pro, Intune) is the authoritative source for device enrollment and compliance status. Sentinel trusts the MDM API response.

3. **Fail-open vs fail-closed:** By default, if MDM lookup fails (network error, API rate limit), credentials are denied. This is fail-closed security. Configure `fail_open: true` for availability-prioritized environments.

### Fail-Closed Security

When device posture verification is enabled:

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| Device not found in MDM | Credentials denied | Unknown devices are untrusted |
| MDM API returns error | Credentials denied | Cannot verify posture |
| MDM API timeout | Credentials denied | Cannot verify posture |
| Device found but non-compliant | Credentials denied | Policy requires compliance |

**No credentials are ever issued when device posture cannot be verified.**

## How Device Posture Works

### Device Identification

Each device is identified by a 32-character lowercase hexadecimal device ID (128 bits of entropy):

```
Example: a1b2c3d4e5f67890a1b2c3d4e5f67890
```

The device ID is computed from the machine's unique identifier:
- macOS: IOPlatformUUID
- Windows: MachineGuid registry key
- Linux: /etc/machine-id

Device IDs provide:
- Unique identification per device
- Correlation across credential requests
- Forensic analysis of device-bound sessions

### MDM Integration Flow

When a credential request arrives at Lambda TVM with device posture checking enabled:

```
1. Request arrives with device_id claim
         |
         v
2. Lambda TVM extracts device_id from request
         |
         v
3. Query MDM API: "Find device where SentinelDeviceID = {device_id}"
         |
         v
4. MDM returns: enrolled=true, compliant=true, os_version="14.2.1"
         |
         v
5. Evaluate policy device conditions against MDM response
         |
         v
6. If all conditions pass: issue credentials
   If any condition fails: deny with reason
```

### Policy Evaluation with Device Conditions

Device conditions are evaluated alongside user and profile conditions. All specified conditions must pass:

```yaml
version: "1"
rules:
  - name: production-managed-devices-only
    users: []
    profiles: [prod-admin, prod-ops]
    conditions:
      device:
        require_mdm: true
        require_encryption: true
        min_os_version: "14.0.0"
        allowed_os_types: [darwin, windows]
    effect: allow
```

**Evaluation logic:**
1. User matches rule? (empty = any user)
2. Profile matches rule?
3. Time conditions pass? (if specified)
4. **Device conditions pass?** (if specified)
5. All pass? Apply effect. Any fail? Continue to next rule.

### Decision Logging with Device Context

Credential decisions include device posture context:

```json
{
  "timestamp": "2026-01-26T10:30:00Z",
  "user": "alice",
  "profile": "prod-admin",
  "decision": "allow",
  "rule_matched": "production-managed-devices-only",
  "device_bound": true,
  "device_posture": {
    "mdm_enrolled": true,
    "mdm_compliant": true,
    "disk_encrypted": true,
    "os_type": "darwin",
    "os_version": "14.2.1"
  }
}
```

**Privacy note:** The actual device_id is not logged by default. Instead, `device_bound: true` indicates the session is device-bound. Enable verbose logging to include device IDs for forensic investigations.

## Configuring MDM Integration

### Supported Providers

| Provider | Status | Configuration |
|----------|--------|---------------|
| Jamf Pro | Implemented | API v1 with bearer token |
| Microsoft Intune | Planned | Microsoft Graph API |
| Kandji | Planned | REST API |

### Jamf Pro Setup

#### Step 1: Create API User

In Jamf Pro console:

1. Go to **Settings** > **System** > **User accounts and groups**
2. Create a new user with:
   - **Username:** `sentinel-readonly`
   - **Access Level:** Full Access
   - **Privilege Set:** Custom
3. Grant **Read** permission for:
   - Computers (inventory)
   - Extension Attributes

#### Step 2: Create Extension Attribute

The extension attribute stores the Sentinel device ID for each managed device:

1. Go to **Settings** > **Computer Management** > **Extension Attributes**
2. Create new attribute:
   - **Display Name:** `SentinelDeviceID`
   - **Data Type:** String
   - **Input Type:** Script
   - **Inventory Display:** General

**Extension Attribute Script:**

```bash
#!/bin/bash
# Compute Sentinel device ID from machine UUID
# This script runs during Jamf inventory collection

# Get IOPlatformUUID on macOS
MACHINE_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')

if [ -z "$MACHINE_UUID" ]; then
    echo "<result>unknown</result>"
    exit 0
fi

# Compute HMAC-SHA256 with fixed key (matches Sentinel client)
# The key is public - security comes from MDM enrollment verification
SENTINEL_KEY="sentinel-device-v1"
DEVICE_ID=$(echo -n "$MACHINE_UUID" | openssl dgst -sha256 -hmac "$SENTINEL_KEY" | awk '{print $2}' | cut -c1-32)

echo "<result>$DEVICE_ID</result>"
```

**For Windows devices (PowerShell):**

```powershell
# Get MachineGuid from registry
$machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid').MachineGuid

# Compute HMAC-SHA256
$key = [System.Text.Encoding]::UTF8.GetBytes("sentinel-device-v1")
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $key
$hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($machineGuid))
$deviceId = [BitConverter]::ToString($hash).Replace("-", "").ToLower().Substring(0, 32)

Write-Output "<result>$deviceId</result>"
```

#### Step 3: Populate Extension Attribute

Run an inventory update to populate the extension attribute:

```bash
# On managed Mac
sudo jamf recon
```

Or trigger via Jamf Pro:
1. Go to **Computers** > **Search Inventory**
2. Select target computers
3. Click **Action** > **Send Remote Command** > **Update Inventory**

#### Step 4: Store API Token in Secrets Manager

Create a secret in AWS Secrets Manager:

```bash
aws secretsmanager create-secret \
  --name sentinel/mdm/jamf-token \
  --description "Jamf Pro API token for Sentinel device posture verification" \
  --secret-string '{"username":"sentinel-readonly","password":"your-api-token"}'
```

**Secret format:**

```json
{
  "username": "sentinel-readonly",
  "password": "your-jamf-api-token"
}
```

#### Step 5: Configure Lambda TVM

Set environment variables on the Lambda TVM function:

| Variable | Description | Example |
|----------|-------------|---------|
| `MDM_PROVIDER` | MDM provider type | `jamf` |
| `MDM_BASE_URL` | Jamf Pro server URL | `https://yourcompany.jamfcloud.com` |
| `MDM_SECRET_ARN` | Secrets Manager ARN for API token | `arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinel/mdm/jamf-token` |
| `MDM_TIMEOUT` | API request timeout | `10s` (default) |
| `MDM_CACHE_TTL` | Cache TTL for device lookups | `5m` (default) |

```bash
aws lambda update-function-configuration \
  --function-name sentinel-tvm \
  --environment "Variables={
    MDM_PROVIDER=jamf,
    MDM_BASE_URL=https://yourcompany.jamfcloud.com,
    MDM_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinel/mdm/jamf-token,
    MDM_CACHE_TTL=5m
  }"
```

**Grant Secrets Manager access to Lambda execution role:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSecretsManagerRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinel/mdm/jamf-token*"
    }
  ]
}
```

## Policy Device Conditions

All device conditions from `policy/device.go`:

| Condition | Type | Description |
|-----------|------|-------------|
| `require_mdm` | boolean | Device must be MDM enrolled |
| `require_mdm_compliant` | boolean | Device must be MDM compliant (implies enrollment) |
| `require_encryption` | boolean | Disk encryption must be enabled |
| `require_firewall` | boolean | Firewall must be enabled |
| `min_os_version` | string | Minimum OS version (e.g., "14.0.0") |
| `allowed_os_types` | list | Restrict to specific OS types: `darwin`, `windows`, `linux` |

### Condition Behavior

**Empty conditions:** If no device conditions are specified, device posture is not checked. This maintains backward compatibility.

**All conditions AND:** When multiple conditions are specified, ALL must pass:

```yaml
conditions:
  device:
    require_mdm: true          # AND
    require_encryption: true   # AND
    min_os_version: "14.0.0"   # All must pass
```

**Nil vs false:** For boolean conditions:
- Not specified (nil): Condition not checked
- `false`: Explicitly not required (unusual, but valid)
- `true`: Condition must be met

### Example Policies

**Production requires managed, encrypted devices:**

```yaml
version: "1"
rules:
  - name: production-requires-managed-device
    users: []
    profiles: [prod-admin, prod-ops, prod-readonly]
    conditions:
      device:
        require_mdm: true
        require_encryption: true
        min_os_version: "14.0.0"
    effect: allow
    reason: Production access requires managed, encrypted device with current OS
```

**Tiered access by device posture:**

```yaml
version: "1"
rules:
  # Full access for fully compliant devices
  - name: full-access-compliant
    users: []
    profiles: [prod-admin]
    conditions:
      device:
        require_mdm_compliant: true
        require_encryption: true
        require_firewall: true
    effect: allow
    reason: Full access for compliant devices

  # Read-only for enrolled but non-compliant devices
  - name: readonly-enrolled
    users: []
    profiles: [prod-readonly]
    conditions:
      device:
        require_mdm: true
    effect: allow
    reason: Read-only access for enrolled devices

  # Deny all other device access to production
  - name: deny-unmanaged-prod
    users: []
    profiles: [prod-admin, prod-ops, prod-readonly]
    conditions: {}
    effect: deny
    reason: Production requires managed device
```

**macOS-only for certain profiles:**

```yaml
version: "1"
rules:
  - name: macos-only-profiles
    users: []
    profiles: [macos-dev, ios-dev]
    conditions:
      device:
        allowed_os_types: [darwin]
    effect: allow
    reason: iOS/macOS development requires macOS
```

## Device Audit Commands

Sentinel provides CLI commands for auditing device-bound sessions and detecting anomalies.

### device-sessions

List sessions for a specific device ID:

```bash
sentinel device-sessions <device-id> --region us-east-1 --table sentinel-sessions
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--region` | AWS region for DynamoDB | Yes |
| `--table` | DynamoDB table name for sessions | Yes |
| `--status` | Filter by status: `active`, `revoked`, `expired` | No |
| `--limit` | Maximum number of results | No (default: 100) |
| `--output` | Output format: `human`, `json`, `csv` | No (default: human) |
| `--aws-profile` | AWS profile for credentials | No |

**Example:**

```bash
# List all sessions for a device
sentinel device-sessions a1b2c3d4e5f67890a1b2c3d4e5f67890 \
  --region us-east-1 \
  --table sentinel-sessions

# Output:
# ID                User          Profile              Status    Started               Requests
# ----------------  ------------  --------------------  --------  --------------------  --------
# sess-abc123       alice         prod-admin           active    2026-01-26 10:30:00   15
# sess-def456       alice         prod-readonly        expired   2026-01-25 14:22:00   8
```

**JSON output for scripting:**

```bash
sentinel device-sessions a1b2c3d4e5f67890a1b2c3d4e5f67890 \
  --region us-east-1 \
  --table sentinel-sessions \
  --output json
```

```json
{
  "sessions": [
    {
      "id": "sess-abc123",
      "user": "alice",
      "profile": "prod-admin",
      "status": "active",
      "started_at": "2026-01-26T10:30:00Z",
      "last_access_at": "2026-01-26T10:45:00Z",
      "expires_at": "2026-01-26T11:30:00Z",
      "request_count": 15,
      "device_id": "a1b2c3d4e5f67890a1b2c3d4e5f67890"
    }
  ]
}
```

### devices

List all known devices with session history and anomaly detection:

```bash
sentinel devices --region us-east-1 --table sentinel-sessions
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--region` | AWS region for DynamoDB | Yes |
| `--table` | DynamoDB table name for sessions | Yes |
| `--since` | Only show devices with sessions within duration (e.g., `7d`, `30d`) | No |
| `--limit` | Maximum number of sessions to query | No (default: 1000) |
| `--profile-threshold` | Profile count threshold for HIGH_PROFILE_COUNT anomaly | No (default: 5) |
| `--output` | Output format: `human`, `json` | No (default: human) |
| `--aws-profile` | AWS profile for credentials | No |

**Example:**

```bash
sentinel devices --region us-east-1 --table sentinel-sessions --since 7d

# Output:
# Device ID (truncated)   Sessions  Users  Profiles  Latest Access         Flags
# --------------------    --------  -----  --------  --------------------  -----
# a1b2c3d4e5f67890...          15      1         3  2026-01-26 10:30:00
# b2c3d4e5f6789012...           8      2         6  2026-01-25 14:22:00   MULTI_USER,HIGH_PROFILE_COUNT
```

### Anomaly Detection

The `devices` command automatically detects anomalies:

| Anomaly | Condition | Significance |
|---------|-----------|--------------|
| `MULTI_USER` | Device has sessions from >1 user | Possible credential sharing or device compromise |
| `HIGH_PROFILE_COUNT` | Device accessed >5 profiles (configurable) | Unusual access pattern, possible recon activity |

**Investigating anomalies:**

```bash
# Find the anomalous device
sentinel devices --region us-east-1 --table sentinel-sessions --output json | \
  jq '.devices[] | select(.anomalies | length > 0)'

# Get full session history for that device
sentinel device-sessions b2c3d4e5f6789012... \
  --region us-east-1 \
  --table sentinel-sessions \
  --output json
```

## Troubleshooting

### Common Errors

**Error: `device not found in MDM`**

The device ID was not found in the MDM provider's inventory.

**Causes:**
- Extension Attribute not configured in Jamf Pro
- Device not enrolled in MDM
- Inventory not synced since extension attribute was added
- Device ID mismatch between client and MDM

**Resolution:**

1. Verify extension attribute exists in Jamf Pro:
   - Go to **Settings** > **Computer Management** > **Extension Attributes**
   - Look for `SentinelDeviceID`

2. Check device inventory in Jamf Pro:
   - Go to **Computers** > **Search Inventory**
   - Find the device
   - Check **Extension Attributes** tab for `SentinelDeviceID` value

3. Force inventory sync:
   ```bash
   # On the managed device
   sudo jamf recon
   ```

4. Compare device IDs:
   ```bash
   # On the client, compute expected device ID
   MACHINE_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')
   echo -n "$MACHINE_UUID" | openssl dgst -sha256 -hmac "sentinel-device-v1" | awk '{print $2}' | cut -c1-32
   ```

---

**Error: `device conditions not matching`**

The device was found but doesn't meet policy conditions.

**Causes:**
- Device not MDM compliant
- Disk encryption not enabled
- OS version below minimum
- OS type not in allowed list

**Resolution:**

1. Check which condition failed (see decision log):
   ```json
   {
     "decision": "deny",
     "reason": "device condition not met: require_encryption",
     "device_posture": {
       "disk_encrypted": false
     }
   }
   ```

2. Verify device posture in MDM:
   - Check FileVault status for macOS
   - Check BitLocker status for Windows

3. Update policy if condition is too restrictive:
   ```yaml
   conditions:
     device:
       require_mdm: true
       # require_encryption: true  # Temporarily disable
   ```

---

**Error: `rate limit exceeded`**

MDM API is throttling requests.

**Causes:**
- Too many credential requests in short period
- MDM cache TTL too short
- Other integrations sharing API quota

**Resolution:**

1. Increase cache TTL:
   ```bash
   aws lambda update-function-configuration \
     --function-name sentinel-tvm \
     --environment "Variables={MDM_CACHE_TTL=15m}"
   ```

2. Check Jamf Pro API rate limits (typically 60 req/min)

3. Consider implementing request queuing for burst scenarios

---

**Error: `MDM authentication failed`**

API credentials are invalid or expired.

**Causes:**
- API token revoked or expired
- Username/password changed
- Secrets Manager secret not updated

**Resolution:**

1. Test API token manually:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://yourcompany.jamfcloud.com/api/v1/computers-inventory
   ```

2. Update secret in Secrets Manager:
   ```bash
   aws secretsmanager update-secret \
     --secret-id sentinel/mdm/jamf-token \
     --secret-string '{"username":"sentinel-readonly","password":"new-token"}'
   ```

3. Rotate Jamf Pro API token if compromised

### Log Messages

Lambda TVM logs MDM integration status:

| Log Message | Meaning |
|-------------|---------|
| `INFO: MDM provider configured (provider: jamf, base_url: ...)` | MDM integration active |
| `INFO: Device posture verified (device_id: ..., enrolled: true)` | Device passed posture check |
| `WARN: Device not found in MDM (device_id: ...)` | Device lookup returned no results |
| `WARN: MDM API error (status: 429, retrying in ...)` | Rate limiting, will retry |
| `ERROR: MDM authentication failed` | Check API credentials |

## Security Considerations

### Fail-Closed vs Fail-Open

**Fail-closed (default):** If MDM lookup fails, credentials are denied. This prioritizes security over availability.

**Fail-open:** If MDM lookup fails, credentials are issued. Use only in environments where availability is more critical than device posture.

Configure via Lambda TVM environment:
```bash
MDM_FAIL_OPEN=false  # Default, fail-closed
MDM_FAIL_OPEN=true   # Fail-open for availability
```

### MDM API Token Security

The MDM API token has read access to device inventory. Protect it:

1. **Store in Secrets Manager:** Never in environment variables or code
2. **Rotate regularly:** Update token quarterly or when staff change
3. **Audit access:** Monitor Secrets Manager access logs
4. **Least privilege:** Token should only have read permission for computer inventory

### Device ID Privacy

Device IDs are sensitive identifiers that could enable device tracking:

1. **Decision logs:** By default, only `device_bound: true` is logged, not the actual device ID
2. **Session records:** Device IDs are stored for forensic analysis but should be access-controlled
3. **Retention:** Apply data retention policies to session tables

### Anomaly Detection for Compromised Devices

Use the `devices` command regularly to detect suspicious patterns:

```bash
# Weekly anomaly check
sentinel devices --region us-east-1 --table sentinel-sessions --since 7d --output json | \
  jq '.devices[] | select(.anomalies | length > 0)' > anomalies.json

if [ -s anomalies.json ]; then
  echo "Device anomalies detected - review required"
  # Alert security team
fi
```

**Indicators of compromise:**
- `MULTI_USER`: Multiple users from same device (credential sharing or theft)
- `HIGH_PROFILE_COUNT`: Accessing many profiles (enumeration/recon)
- Sudden spike in request count
- Access from device after hours when user is known to be offline
