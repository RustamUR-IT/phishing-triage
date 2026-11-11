# Notify-CreateIncident-OnAlert

Microsoft Sentinel playbook (Azure Logic App) that runs on an **alert** and

1. **creates a Sentinel incident** for it when the alert severity reaches a threshold
   (default *Medium*), and links the alert to that incident,
2. **sends an e-mail** to the SOC with the alert details and the incident link,
3. **posts an Adaptive Card to a Teams channel** if a webhook URL is configured.

```text
Sentinel alert ──► severity ≥ threshold? ──yes──► PUT incident (ID = alert ID) ──► link alert
                          │                                  │
                          no                                 ▼
                          └──────────────────────────► e-mail ──► Teams (optional)
```

The notification is sent even when incident creation fails, so an alert is never silently lost.
The incident ID is the alert's `SystemAlertId` and the call is a `PUT`, so re-running the
playbook on the same alert updates the existing incident instead of creating a duplicate.

## What gets deployed

| Resource | Purpose |
|---|---|
| `Microsoft.Logic/workflows` | The playbook, with a system-assigned managed identity |
| `Microsoft.Web/connections` *azuresentinel* | Alert trigger, authenticated with the managed identity |
| `Microsoft.Web/connections` *office365* | Sending the e-mail; needs a one-time sign-in after deployment |
| `Microsoft.Authorization/roleAssignments` | *Microsoft Sentinel Responder* on the workspace for the managed identity (optional) |

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `PlaybookName` | `Notify-CreateIncident-OnAlert` | Name of the Logic App |
| `WorkspaceName` | – | Sentinel workspace; must be in the resource group you deploy to |
| `NotificationRecipients` | – | Semicolon-separated e-mail addresses |
| `TeamsWebhookUrl` | *(empty)* | Teams *Workflows* webhook for a channel; empty = e-mail only |
| `CreateIncident` | `true` | Turn off when the analytics rule already creates incidents |
| `MinimumIncidentSeverity` | `Medium` | `Informational`, `Low`, `Medium` or `High` |
| `AssignSentinelResponderRole` | `true` | Needs Owner / User Access Administrator; otherwise assign manually |

## Deploy

Azure CLI, into the resource group that holds the Sentinel workspace:

```bash
az deployment group create \
  --resource-group <rg-sentinel> \
  --template-file playbooks/Notify-CreateIncident-OnAlert/azuredeploy.json \
  --parameters WorkspaceName=<workspace> NotificationRecipients="soc@example.com"
```

Or in the portal: *Deploy a custom template* → *Build your own template* → paste
`azuredeploy.json`.

## After deployment

1. **Authorize the Office 365 connection:** resource group → API connection
   `office365-<PlaybookName>` → *Edit API connection* → *Authorize* → sign in with the mailbox
   that should send the notifications (a shared or service mailbox is a good fit) → *Save*.
2. **Role assignment:** if `AssignSentinelResponderRole` was off, give the playbook's managed
   identity (`playbookPrincipalId` in the deployment output) the role *Microsoft Sentinel
   Responder* on the workspace.
3. **Let Sentinel run the playbook:** Sentinel → *Settings* → *Settings* → *Playbook permissions*
   → select the resource group of the playbook.
4. **Attach it to alerts:** open the analytics rule → *Automated response* → *Alert automation*
   → add `Notify-CreateIncident-OnAlert`. To test it on an existing alert, open the alert in
   Sentinel and choose *Run playbook*.

## Combining with phishtriage

Typical use: an analytics rule fires on reported phishing (e.g. user submissions or a mail flow
detection), this playbook opens the incident and pages the SOC, and the analyst attaches the
`phishtriage … -f json` / Markdown report to the incident. The JSON `summary.verdict` and
`findings[].attack` fields map directly onto incident comments and tags if you later automate
that step as well.

## Notes and limits

- **Duplicates:** if the analytics rule has *Create incidents* enabled, Sentinel already creates
  an incident; set `CreateIncident=false` and use the playbook for notification only.
- **Alert trigger vs. incident trigger:** this playbook uses the *alert* trigger on purpose so it
  can decide itself whether an incident is warranted. For rules that already create incidents,
  an automation rule with an incident-trigger playbook is the more common Sentinel pattern.
- The Teams webhook URL is a secret: anyone who has it can post to the channel. It is passed as
  `securestring` so it is not stored in plain text in the deployment history; still use a
  dedicated channel webhook and rotate it if it leaks.
