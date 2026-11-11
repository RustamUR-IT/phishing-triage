# Detections: KQL analytics rules

`phishtriage` looks at one reported mail. These three Microsoft Sentinel analytics rules cover what
happens around it in the tenant: the attacker guessing passwords, a user clicking the phishing
link, and the inbox rule an attacker creates once they are in the mailbox.

| Rule | ATT&CK | Tactic | Data |
|---|---|---|---|
| [`entra_bruteforce_password_spray.kql`](entra_bruteforce_password_spray.kql) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing, [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying | Credential Access | `SigninLogs`, `AADNonInteractiveUserSignInLogs` |
| [`phishing_link_clicked.kql`](phishing_link_clicked.kql) | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Spearphishing Link, [T1204.001](https://attack.mitre.org/techniques/T1204/001/) Malicious Link | Initial Access, Execution | `UrlClickEvents`, `EmailEvents`, `EmailPostDeliveryEvents` |
| [`inbox_rule_hiding_forwarding.kql`](inbox_rule_hiding_forwarding.kql) | [T1564.008](https://attack.mitre.org/techniques/T1564/008/) Email Hiding Rules, [T1114.003](https://attack.mitre.org/techniques/T1114/003/) Email Forwarding Rule | Defense Evasion, Collection | `OfficeActivity` (Exchange) |

## What each rule detects

**Entra ID brute force / password spray.** Failed sign-ins (`50126`, `50053`, `50056`, `50064`)
grouped by source IP over one hour. At least 20 failures against at most three accounts is brute
force, failures against ten or more accounts is a spray. Interactive and non-interactive sign-ins
are both read, because sign-ins made by clients and scripts without user interaction are logged
only in the non-interactive table. If a targeted account then signs in successfully from the same IP, the alert
is raised to *High*: the password was probably guessed.

**Phishing link clicked.** A Safe Links click that was allowed on a mail rated phish or malware,
or a click through the Safe Links warning page. Verdicts often come after the click (ZAP, admin
submission, user report), so clicks from the last day are matched against verdicts that arrived
since the last run; each click alerts once. *High* when the mail has a verdict.

**Inbox rule hiding or forwarding mail.** `New-InboxRule` / `Set-InboxRule` that forwards or
redirects outside the organisation, or that deletes mail or moves it to a folder nobody reads
(RSS Feeds, Conversation History, Archive, ...) and filters on finance/security keywords or has a
throwaway name like `.`. This is the classic business-email-compromise step after a successful
phish. *High* when the rule both hides and forwards, or hides by keyword.

## Deploying in Microsoft Sentinel

Each file starts with a comment header holding the rule settings. In *Analytics → Create →
Scheduled query rule*:

1. Paste the file as the rule query (the header comments are ignored by KQL).
2. Set tactics and techniques from the `Tactics` and `ATT&CK` lines.
3. Set *Run query every* and *Lookup data from the last* from the `Schedule` line. For the
   phishing-click rule the lookback is 8 days (7 days of mail plus 1 day of clicks), and
   `alertWindow` in the query must equal the run frequency.
4. Severity: set the rule to *Medium* and, under *Alert details*, map the severity to the
   `Severity` column so confirmed cases come in as *High*.
5. Map the entities listed in the `Entities` line (Account, IP, URL, MailMessage).
6. Event grouping: one alert per result row.

Each rule has a short tuning block at the top (`trustedIps`, `internalDomains`, thresholds,
keywords). Fill in your corporate egress IPs and accepted domains before enabling.

## Validation

The queries are checked with Microsoft's [Kusto.Language](https://github.com/microsoft/Kusto-Query-Language)
analyser, the same one behind the Sentinel query editor, against the columns of the tables used.
That catches syntax errors, misspelt columns and unknown functions; it does not prove the
thresholds fit your tenant.

```bash
npm install --no-save @kusto/language-service-next@12.4.1
```

```bash
node scripts/check_kql.cjs
```

`tests/test_detections.py` checks that every rule header is complete, that ATT&CK technique and
tactic agree, and that the severity and entity columns are in the final projection. CI runs both.

The rules have not been run against live tenant data in this repository (there is none, by
design). Before enabling one, run it as a hunting query over the last 14 days and look at the hits.
