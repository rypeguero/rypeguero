# Just Another Day

## Nimbus Health Threat Hunt Report

**Incident type:** Externally driven valid-account compromise  
**Hunt window:** 8–18 March 2026  
**Primary activity date:** 11 March 2026  
**Environment:** Nimbus Health Windows estate  
**Telemetry:** Microsoft Sentinel and Microsoft Defender for Endpoint  
**Analyst:** Ryan Peguero  
**Severity:** High

---

## Executive Summary

A routine posture review of the Nimbus Health billing account `j.morris` uncovered an externally driven valid-account compromise rather than ordinary insider activity or stale-access misuse.

The account was used through successful `RemoteInteractive` sessions originating from public IP addresses, including `193.36.225.245`. After accessing the billing workstation, the operator performed host and network discovery, identified internal systems, opened remote sessions to additional Nimbus hosts, accessed restricted billing workflow areas, collected sensitive HR material, and staged payroll data inside the billing share under a misleading filename.

The operator relied on valid credentials, Remote Desktop, and native Windows utilities. No malware, dropped binaries, exploitation, or malicious payload execution was identified. The evidence supports an external attacker operating a legitimate employee account rather than a curious employee or an accidental insider mistake.

---

## Scope

### Compromised account

```text
j.morris
```

### Systems involved

| Host | Role | Finding |
|---|---|---|
| `NH-WKS-BILL-01` | Billing workstation | Initial hands-on activity, discovery, and access to sensitive shares |
| `NH-WKS-IT-01` | IT workstation | Remote landing only; no confirmed hands-on activity |
| `NH-FS-01` | File server | Share enumeration, privilege discovery, and HR data access |

### Key source information

- External source IP observed: `193.36.225.245`
- Internal lateral-movement source: `10.1.0.207`
- Logon type: `RemoteInteractive`

---

## Investigation Timeline

### 1. Initial access

The `j.morris` billing account established successful `RemoteInteractive` sessions on the billing workstation from public IP addresses.

This did not match the expected behavior of an employee physically working at the billing desk and immediately weakened the original insider-misuse theory.

### 2. Early command-shell noise ruled out

The first command-shell activity showed a burst of file and directory deletions. Review of the command lines, parent processes, and file paths showed that the activity was normal OneDrive updater cleanup.

```text
OneDrive updater cleanup
```

The repetitive deletion of older OneDrive setup and updater files was application-maintenance noise, not attacker activity.

### 3. Initial reconnaissance

After the noise, the operator ran a short, deliberate sequence of native commands:

```text
whoami
hostname
net  use
net  view
net  view \\NH-FS-01
```

These commands allowed the operator to confirm the compromised identity, identify the current host, review active network connections, enumerate visible systems, and inspect the Nimbus file server.

The file server was the first explicitly named target:

```text
NH-FS-01
```

### 4. Domain and local-network discovery

The operator later widened discovery to the Nimbus domain:

```text
"net.exe" view /domain:nimbus
```

Immediately afterward, the operator enumerated the ARP table and performed reverse-DNS lookups:

```text
"ARP.EXE" -a
nslookup.exe <internal IP>
```

This activity built a map of the local network and directly preceded a Remote Desktop pivot to another internal host.

### 5. Unauthorized billing workflow access

The compromised account reached into the billing approval stage, which was outside the responsibilities of a submissions-only billing analyst.

```text
Approved
```

The operator handled the invoice:

```text
approved_pending_invoice_INV-773221_20260311.txt
```

The account also modified the workflow audit record:

```text
review_audit_20260311.txt
```

Access to both the approved invoice and the review audit trail indicates interference with the sign-off stage of the billing workflow.

### 6. HR data collection and staging

The operator pulled payroll material from HR and placed it in the billing exceptions folder under a misleading filename:

```text
payroll_exception_reference_20260311.txt.txt
```

The double `.txt.txt` extension was significant. The file previously appeared under the temporary name:

```text
temp_payroll_review_jmorris_20260311.txt.txt
```

The operator also accessed an unrelated HR file:

```text
quarterly_awards_shortlist_20260310.txt
```

This showed that the collection was broader than payroll and included additional employee personnel information.

### 7. Lateral movement

The account opened remote interactive sessions on two additional systems:

```text
NH-WKS-IT-01
NH-FS-01
```

The sessions originated from the compromised billing workstation.

#### IT workstation finding

The IT workstation was a red herring. The telemetry showed only normal first-logon and user-profile initialization activity, including Windows shell, Edge, OneDrive, and RDP components.

No deliberate commands, targeted file access, reconnaissance, or collection activity was identified.

```text
Remote logon only, no hands-on activity
```

### 8. File-server activity

On `NH-FS-01`, the operator checked the account's group memberships:

```text
"whoami.exe" /groups
```

The operator then enumerated the shares offered by the server:

```text
"net.exe" share
```

The last confirmed file-server action involved opening a payroll review belonging to another employee:

```text
payroll_review_dpatel_20260311.txt
```

This file belonged to `d.patel`, confirming that the compromise affected multiple employees.

---

## Key Findings

| Finding | Evidence |
|---|---|
| Valid-account compromise | Successful `RemoteInteractive` sessions using `j.morris` |
| External control | Sessions originated from public IP addresses |
| Native-tool execution | `whoami`, `hostname`, `net`, `arp`, `nslookup`, and RDP |
| Role violation | Access to the billing `Approved` folder |
| Workflow interference | Invoice handling and audit-trail modification |
| Sensitive-data collection | Payroll reviews and employee awards information |
| Data staging | HR payroll material placed in Billing under a misleading name |
| Lateral movement | Remote sessions to the IT workstation and file server |
| Red-herring system | No hands-on activity on `NH-WKS-IT-01` |
| No malware evidence | No dropped binaries, exploitation, or malicious payloads |

---

## Collection Scope

The activity was not limited to one payroll document. The compromised account accessed or handled:

- Payroll material associated with `j.morris`
- Payroll information belonging to `d.patel`
- An employee awards shortlist
- Billing approval records
- A billing workflow audit record

The incident therefore involved broad cross-department personnel-data collection spanning Billing and HR and affecting multiple employees.

---

## Root-Cause Assessment

```text
Externally driven valid-account compromise from public IPs, with no malware, dropped binaries, or exploitation
```

The attacker appears to have obtained valid credentials for `j.morris` and used Remote Desktop to operate the account interactively.

The activity does not fit a routine insider mistake because:

- The sessions originated externally
- The operator performed deliberate reconnaissance
- The account moved laterally between systems
- Sensitive data was renamed and staged under cover
- Multiple employees and departments were affected

The activity does not fit a malware-driven intrusion because:

- No malicious binaries were dropped
- No exploitation was observed
- No malicious execution chain was identified
- Native Windows tools and valid credentials were used throughout

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---:|---|
| Valid Accounts | T1078 | Compromised `j.morris` credentials |
| Remote Services: Remote Desktop Protocol | T1021.001 | `RemoteInteractive` sessions and RDP pivots |
| System Owner/User Discovery | T1033 | `whoami` |
| System Information Discovery | T1082 | `hostname` |
| Remote System Discovery | T1018 | `net view`, domain enumeration, ARP enumeration, and reverse-DNS lookups |
| Permission Groups Discovery | T1069 | `"whoami.exe" /groups` |
| Network Share Discovery | T1135 | `"net.exe" share` |
| Data from Network Shared Drive | T1039 | Access to HR and Billing shares |
| Data Staged: Local Data Staging | T1074.001 | HR payroll material staged in Billing |
| Masquerading: Double File Extension | T1036.007 | `.txt.txt` staging filename |

---

## Impact Assessment

### Confirmed impact

- Unauthorized access to Billing and HR information
- Exposure of payroll data belonging to multiple employees
- Access to non-payroll HR personnel information
- Modification of a billing workflow audit record
- Internal staging of sensitive data in an unrelated departmental share
- Lateral access to multiple Nimbus systems

### Not confirmed

The available telemetry confirms collection and internal staging but does not independently prove a separate file transfer from Nimbus Health to an external destination.

Because the account was controlled through externally sourced remote sessions, the confidentiality risk remains high even without separate exfiltration telemetry.

---

## Recommended Actions

### Immediate containment

1. Disable or suspend the `j.morris` account.
2. Revoke active sessions, authentication tokens, and remembered devices.
3. Reset the account password and require phishing-resistant MFA.
4. Block confirmed malicious source IP addresses.
5. Isolate `NH-WKS-BILL-01` and preserve forensic evidence.
6. Review active and historical sessions on `NH-FS-01`.

### Credential and access review

1. Determine how the `j.morris` credentials were compromised.
2. Review the account's group memberships and share permissions.
3. Audit all accounts with access to HR, Billing, and approval workflows.
4. Remove access not required by job role.
5. Review whether Internet-accessible RDP was enabled or indirectly exposed.

### Data-impact review

1. Identify every file accessed, opened, copied, renamed, or modified.
2. Confirm whether the staged payroll file was later removed or transferred.
3. Review data belonging to `j.morris`, `d.patel`, and employees listed in the awards document.
4. Preserve the modified billing audit trail and compare it with authoritative records.
5. Engage HR, privacy, legal, and compliance teams to assess notification obligations.

### Detection improvements

Create alerts for:

- Remote interactive logons from public IP addresses
- Billing accounts accessing HR shares
- HR files created in Billing folders
- Double file extensions in sensitive shares
- `net view`, `net share`, ARP, and repeated `nslookup` activity after RDP logons
- Remote sessions followed by cross-department file access
- Billing submitters accessing approval or audit-trail directories

---

## Final Conclusion

Nimbus Health experienced an external valid-account compromise involving the billing account `j.morris`.

The external operator used valid credentials and native Windows utilities to conduct reconnaissance, move laterally, access restricted billing workflow records, collect HR personnel information, and stage payroll data under a misleading billing filename.

The absence of malware, exploitation, and dropped binaries is not evidence that the incident was harmless. It is evidence that the attacker did not need them. Valid credentials opened the door, and ordinary administrative tools did the rest.
