# Third-Party Notices

This project has **no third-party dependencies**.

All scripts rely only on PowerShell and modules that ship with Windows:

- The `ScheduledTasks` module (built into Windows) for `*-ScheduledTask*` cmdlets.
- The `ActiveDirectory` RSAT module (optional, Microsoft-provided) for `Test-ADServiceAccount`,
  used only when gMSA validation is requested.
- `secedit.exe` (built into Windows) for granting and revoking the "Log on as a batch job"
  user right.

If a third-party dependency is ever added, record it here with its package name, version,
copyright holder, and license type.
