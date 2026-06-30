# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in these scripts, please report it privately.  Do not
open a public issue for security problems.

- Preferred: use the forge's private vulnerability reporting feature if available.
- Otherwise, email **vuln@mvct.com** with a description of the issue, steps to reproduce, and
  the potential impact.

You will receive an acknowledgement as soon as the report is reviewed.  Please allow a
reasonable amount of time for a fix to be prepared and released before any public disclosure.

## Scope

These scripts run with elevated privileges and modify Scheduled Tasks and user-rights
assignments on the host where they are run.  Reports that are particularly valuable include:

- Privilege-escalation paths introduced by how a task principal or user right is configured.
- Injection or unexpected execution arising from how parameters are passed to the task action.
- Any case where a managed-account password or other secret could be exposed.
