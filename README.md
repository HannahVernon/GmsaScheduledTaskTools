# GmsaScheduledTaskTools

PowerShell scripts for creating, inspecting, and removing Windows Scheduled Tasks that run
under a **Group Managed Service Account (gMSA)**.  Running scheduled tasks as a gMSA means
there is no password to store, manage, or rotate - Active Directory handles the managed
password automatically, which reduces the credential-exposure surface for unattended jobs.

## Why gMSA-backed tasks

A gMSA can run a Windows Scheduled Task on Windows Server 2012 or later.  The catch is that
the Task Scheduler GUI (`taskschd.msc`) cannot configure a gMSA principal cleanly - it tries
to prompt for a password the account does not have.  These scripts register the task via
PowerShell using a principal with `-LogonType Password`, which tells Task Scheduler to
retrieve the managed password from AD at run time.  No password is ever supplied.

## Scripts

Script | Purpose
-------|--------
`New-GmsaScheduledTask.ps1` | Create (or idempotently update) a Scheduled Task that runs as a gMSA.  Optionally validates the gMSA on the host and grants the "Log on as a batch job" right.
`Get-GmsaScheduledTask.ps1` | Report the principal, action, and trigger of one or more tasks, with a focus on gMSA detail.  Read-only.
`Remove-GmsaScheduledTask.ps1` | Unregister a task and, optionally, revoke the gMSA's "Log on as a batch job" right.

Every script ships with comment-based help.  Run `Get-Help .\New-GmsaScheduledTask.ps1 -Full`
for full parameter documentation and examples.

## Requirements

- Windows Server 2012 / Windows 8 or later (gMSA support).
- A KDS root key in the domain, and the gMSA already created with the target host listed in
  `PrincipalsAllowedToRetrieveManagedPassword`, then installed on the host via
  `Install-ADServiceAccount`.
- Run the scripts **elevated** (Administrator) on the host that will run the task.
- The RSAT **ActiveDirectory** module is needed only for the optional `Test-ADServiceAccount`
  validation (`-TestGmsa` / the create-time gMSA check).

## Quick start

Create a daily 2 AM task that runs a script as a gMSA, granting the batch logon right and
running elevated:

```powershell
.\New-GmsaScheduledTask.ps1 -TaskName 'NightlyExport' -GmsaAccount 'CONTOSO\svc-export$' `
    -Execute 'powershell.exe' -Argument '-NoProfile -File C:\Scripts\Export.ps1' `
    -TriggerType Daily -At 2:00AM -GrantBatchLogonRight -RunLevel Highest -Verbose
```

Report on every gMSA-backed task on the host and whether each gMSA is installed:

```powershell
.\Get-GmsaScheduledTask.ps1 -GmsaOnly -Recurse -TestGmsa |
    Select-Object TaskName, UserId, RunLevel, TriggerSummary, GmsaInstalled
```

Remove a task (leaving the batch logon right in place for other workloads):

```powershell
.\Remove-GmsaScheduledTask.ps1 -TaskName 'NightlyExport'
```

## Notes

- The gMSA account name is referenced with a trailing `$` (e.g. `CONTOSO\svc-export$`).  The
  scripts add the `$` automatically if you omit it.
- `New-GmsaScheduledTask.ps1` is idempotent: if a matching task already exists it is left
  unchanged unless you pass `-Force`.
- `Get-GmsaScheduledTask.ps1` does not gather last/next run times by default, because
  `Get-ScheduledTaskInfo` makes a per-task RPC that can be slow on hosts with many tasks.
  Pass `-IncludeRunInfo` (bounded by `-RunInfoTimeoutSeconds`) when you need that data.
- Revoking the "Log on as a batch job" right affects every task or service that logs on as a
  batch job under that account on the host, so `Remove-GmsaScheduledTask.ps1` leaves it in
  place unless you explicitly pass `-RevokeBatchLogonRight`.

## License

MIT - see [LICENSE](LICENSE).
