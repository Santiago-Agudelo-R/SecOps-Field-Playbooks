# PB-SEC-006: Business Email Compromise (BEC), AiTM Session Hijack & Inbox Rule Triage

- **Document ID:** PB-SEC-006
- **Version:** 1.2.1
- **Domain:** Email Security, Identity Threat Detection & Response (ITDR) & Exchange Online Forensics
- **Platforms:** Mimecast Email Security, Microsoft Entra ID, Exchange Online (`ExchangeOnlineManagement`), Microsoft Defender for Office 365
- **Validation:** Self-directed lab (not production-validated)

> **Validation status: self-directed lab.** This playbook was built from personal lab work and vendor documentation. It has not yet been validated in a production environment. Feedback and corrections are welcome via Issues.

---

## 1. Incident Scope & Symptoms

Adversary-in-the-Middle (AiTM) phishing kits (such as Evilginx / Tycoon2FA) proxy real Microsoft Entra ID sign-in pages to capture session cookies (`ESTSAUTHPERSISTENT`) after the user completes MFA. Once inside the mailbox, attackers establish quiet persistence using hidden MAPI inbox rules or external forwarding before launching financial fraud or lateral phishing.

### Common Observable Indicators
- **Mimecast / Defender Alert:** User clicked a rewritten URL in Mimecast Targeted Threat Protection (TTP) pointing to a newly registered domain (`login-contoso-auth.example.com`) followed by an interactive sign-in within 2 minutes.
- **Impossible Travel / Token Replay:** Entra ID sign-in logs show an interactive MFA login from a residential ISP (`198.51.100.42`) and a subsequent non-interactive token claim from a hosting provider ASN (`203.0.113.89`) sharing the same `SessionId` or `CorrelationId`.
- **Mailbox Anomaly:** Recipients report missing emails from threads involving invoices or wire transfers, or external contacts report receiving suspicious follow-up replies from an internal `contoso.com` address.

---

## 2. Architecture & Attack Chain

```text
[Phishing Lure Bypassing or Clicked Through Email Gateway (Mimecast TTP)]
                                    │
                                    ▼
[Reverse-Proxy AiTM Landing Page Captures Credentials + MFA Session Cookie]
                                    │
                                    ▼
[Attacker Replays Session Cookie Against Outlook Web App (OWA) / Graph API]
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
[Hidden Inbox Rules]     [SMTP Mailbox Forwarding]    [OAuth App Consent]
(Move to RSS / Delete)   (ForwardingSmtpAddress)      (Mail.ReadWrite Grant)
```

| Persistence Vector | Exchange / Entra Mechanism | Why Standard Checks Miss It |
| :--- | :--- | :--- |
| **Hidden Inbox Rules** | `New-InboxRule` / MAPI `PR_RULE_MSG_PROVIDER` | Standard `Get-InboxRule` without `-IncludeHidden` omits corrupted or hidden MAPI rules created via MFCMAPI/EWS. |
| **Mailbox-Level Forwarding** | `Set-Mailbox -ForwardingSmtpAddress` | Configured on the mailbox object itself rather than as an Inbox Rule inside OWA. |
| **Illicit OAuth App Consent** | `OAuth2PermissionGrant` (`Mail.Read`, `Mail.ReadWrite`) | Persists even after the user's password is changed and interactive sessions are revoked. |
| **Additional MFA Method** | Entra ID `AuthenticationMethods` | Attacker registers a secondary Authenticator app or phone number during the hijacked session. |

---

## 3. Diagnostic Triage Procedure

### Step 3.1: Email Gateway & Header Triage (Mimecast & Exchange Online)
1. In **Mimecast Administration Console > Message Center > Message Tracking**, locate the initial message by sender, recipient (`a.morales@contoso.com`), or `Message-ID`:
   - Inspect **Authentication-Results:** Confirm whether SPF (`pass`/`softfail`), DKIM, and DMARC aligned, or if the sender compromised a legitimate external vendor thread (Vendor Email Compromise).
   - Check **TTP URL Protection Logs:** Identify every internal user who clicked the rewritten URL within the last 72 hours to scope additional compromised accounts.
2. Connect to Exchange Online PowerShell and Microsoft Graph:
```powershell
Connect-ExchangeOnline -ShowBanner:$false
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All"
```

### Step 3.2: Audit Entra ID Sign-In Logs & Registered MFA Devices
Query recent sign-ins for the affected user (`a.morales@contoso.com`) to identify anomalous IP addresses (`203.0.113.89`), user agents, and authentication details:
```powershell
$upn = "a.morales@contoso.com"

# Interactive sign-ins (the v1.0 endpoint returns interactive sign-ins only)
Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$upn'" -Top 50 |
    Select-Object CreatedDateTime, IpAddress, ClientAppUsed, AppDisplayName,
                  @{N='City';E={$_.Location.City}},
                  @{N='Country';E={$_.Location.CountryOrRegion}},
                  ConditionalAccessStatus,
                  @{N='Status';E={$_.Status.ErrorCode}} |
    Format-Table -AutoSize

# Non-interactive sign-ins (token replay shows up here). Requires the beta endpoint:
# Install-Module Microsoft.Graph.Beta.Reports
Get-MgBetaAuditLogSignIn -Filter "userPrincipalName eq '$upn' and signInEventTypes/any(t: t eq 'nonInteractiveUser')" -Top 50 |
    Select-Object CreatedDateTime, IpAddress, AppDisplayName, ResourceDisplayName,
                  @{N='Status';E={$_.Status.ErrorCode}} |
    Format-Table -AutoSize

# Check registered MFA methods for recently added unauthorized devices
Get-MgUserAuthenticationMethod -UserId $upn |
    ForEach-Object {
        [PSCustomObject]@{
            MethodId   = $_.Id
            ODataType  = $_.AdditionalProperties['@odata.type']
            CreatedUtc = $_.AdditionalProperties['createdDateTime']
            Details    = ($_.AdditionalProperties | ConvertTo-Json -Compress)
        }
    } | Format-Table -AutoSize
```

### Step 3.3: Inspect Inbox Rules (Including Hidden MAPI Rules) & Mailbox Forwarding
Always include `-IncludeHidden` when auditing a suspected BEC mailbox:
```powershell
$upn = "a.morales@contoso.com"

# 1. Enumerate all Inbox Rules, including hidden rules
Get-InboxRule -Mailbox $upn -IncludeHidden |
    Select-Object Name, Enabled, Priority, MoveToFolder, DeleteMessage,
                  ForwardTo, ForwardAsAttachmentTo, RedirectTo, Description |
    Format-List

# 2. Check mailbox-level SMTP forwarding
Get-Mailbox -Identity $upn |
    Select-Object UserPrincipalName, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
```

### Step 3.4: Query Unified Audit Log (UAL) & OAuth App Grants
Check `Search-UnifiedAuditLog` for rule creation, mailbox modifications, or OAuth application consents performed from the attacker's IP:

> Operation names are matched exactly and some Entra ID operations are stored with a trailing period (for example `Consent to application.`). If a search returns nothing, run it once without `-Operations` and copy the exact names from the `Operations` column.
```powershell
$upn = "a.morales@contoso.com"

Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-14) -EndDate (Get-Date) `
    -UserIds $upn `
    -Operations "New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox", "Consent to application", "Add delegated permission grant" `
    -ResultSize 100 |
    Select-Object CreationDate, UserIds, Operations, AuditData |
    Format-List

# Inspect delegated OAuth permissions granted by the user
$userObj = Get-MgUser -UserId $upn
Get-MgOauth2PermissionGrant -Filter "principalId eq '$($userObj.Id)'" |
    Select-Object Id, ClientId, ConsentType, Scope
```

---

## 4. Containment, Eradication & Recovery

Execute containment steps in order so the attacker cannot watch the remediation from an active OWA session or receive password reset notifications:

### Step 4.1: Revoke Active Sessions & Block Sign-In
```powershell
$upn = "a.morales@contoso.com"
$userObj = Get-MgUser -UserId $upn

# Temporarily block sign-in and revoke all refresh/session tokens
Update-MgUser -UserId $userObj.Id -AccountEnabled:$false
Revoke-MgUserSignInSession -UserId $userObj.Id
```

### Step 4.2: Remove Malicious Inbox Rules, Forwarding & Rogue OAuth Grants
```powershell
$upn = "a.morales@contoso.com"

# Remove a confirmed malicious Inbox Rule by Identity
Remove-InboxRule -Mailbox $upn -Identity "<RuleIdentity>" -Confirm:$false

# Clear unauthorized mailbox-level forwarding
Set-Mailbox -Identity $upn -ForwardingAddress $null -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false

# Revoke an unauthorized OAuth2 permission grant if present
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<GrantId>"
```

### Step 4.3: Remediate the Phishing Campaign Across the Tenant
1. **Mimecast Remediation:**
   - Add the sender address/domain and malicious URL host (`login-contoso-auth.example.com`) to **Mimecast Blocked Senders / Managed URLs (Block)**.
   - Use **Mimecast Message Center > Remediation** (or Exchange Online Compliance Search) to purge unread copies of the phishing email from all other recipient mailboxes.
2. **Credential & MFA Reset:**
   - Remove any attacker-registered MFA method in **Microsoft Entra Admin Center > Users > Authentication methods**.
   - Reset the user's password, re-enable the account (`Update-MgUser -AccountEnabled:$true`), and require fresh MFA registration from a known corporate IP.

---

## 5. Verification & Post-Incident Validation

1. **Confirm Clean Mailbox State:**
   Re-run `Get-InboxRule -Mailbox $upn -IncludeHidden` and `Get-Mailbox -Identity $upn` to confirm zero unauthorized rules or forwarding addresses remain.
2. **Audit Sent Items & Deleted Items (Blast Radius Check):**
   Verify whether the attacker sent lateral phishing or wire instructions from the compromised mailbox during the session window:
   ```powershell
   # Get-MessageTraceV2 replaces the deprecated Get-MessageTrace cmdlet
   Get-MessageTraceV2 -SenderAddress $upn -StartDate (Get-Date).AddDays(-3) -EndDate (Get-Date) |
       Select-Object Received, RecipientAddress, Subject, Status, FromIP
   ```
3. **Verify Post-Containment Sign-Ins:**
   Monitor `Get-MgAuditLogSignIn` for 24 hours to confirm all subsequent token refresh attempts from `203.0.113.89` fail with error `50173` (fresh token needed after revocation) or `50057` (user disabled).

---

## 6. Escalation & RCA Criteria

Escalate to Incident Response / Legal & Finance leadership immediately if:
- `MailItemsAccessed` events in the Unified Audit Log show the attacker accessed sensitive financial, M&A, or legal threads.
- Outbound `Get-MessageTraceV2` confirms the attacker replied to external clients or accounting staff with modified payment/ACH instructions.
