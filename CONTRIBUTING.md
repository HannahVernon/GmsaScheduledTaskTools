# Contributing to GmsaScheduledTaskTools

Thanks for your interest in improving these scripts.  This guide covers the basics.

## Prerequisites

- Windows with PowerShell 5.1 or PowerShell 7+.
- For testing gMSA behavior end to end: a domain-joined host, a KDS root key in the domain,
  and a gMSA installed on the host (`Install-ADServiceAccount`).  Most code review can be done
  without a live gMSA, since the scripts validate cleanly with the PowerShell parser.

## Branch model

- `main` - release branch.  Protected.
- `dev` - integration branch.  Protected.
- Feature and fix work happens on `feature/xxx` or `fix/xxx` branches taken off `dev`.

Open pull requests against `dev`.  Promotion to `main` happens via a `dev` -> `main` PR.

Use `git switch` / `git switch -c` to change or create branches, and `git restore` to restore
files.

## Coding standards

- Every script is an advanced function-style script with `[CmdletBinding()]`, a proper
  `param ()` block, and comment-based help (a `<# .SYNOPSIS ... #>` block) before the
  `param ()`.
- Validate every `.ps1` file with the PowerShell parser before committing.  A commit must not
  introduce parse errors:

  ```powershell
  $errors = $null; $tokens = $null
  [System.Management.Automation.Language.Parser]::ParseFile(
      (Resolve-Path .\Script.ps1), [ref]$tokens, [ref]$errors) | Out-Null
  if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message } }
  ```

- Scripts that change system state (register/remove tasks, grant/revoke rights) should support
  `-WhatIf` / `-Confirm` via `SupportsShouldProcess`.
- Keep line endings as CRLF for `.ps1` files (enforced by `.gitattributes`).
- Update the `README.md` and any other affected docs in the same commit as a behavior change.

## Pull request expectations

- One logical change per PR.
- Describe what changed and why, and how you tested it.
- No commented-out code or debug leftovers.
- New dependencies must be justified; this toolset currently has zero third-party
  dependencies, and that is a feature.
