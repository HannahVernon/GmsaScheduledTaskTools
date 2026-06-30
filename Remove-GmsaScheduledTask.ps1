<#
.SYNOPSIS
    Removes a Windows Scheduled Task and, optionally, revokes the gMSA "Log on as a batch
    job" user right that New-GmsaScheduledTask.ps1 may have granted.

.DESCRIPTION
    Companion to New-GmsaScheduledTask.ps1.  On the host where it is run, the script:

      * Unregisters the named Scheduled Task (if it exists).
      * Optionally revokes the "Log on as a batch job" (SeBatchLogonRight) user right from a
        gMSA.  This is OFF by default because the right may be required by other tasks or
        services running under the same account; only revoke it when you are certain nothing
        else on the host depends on it.

    Run this script elevated (Administrator) on the host that runs the task.

.PARAMETER TaskName
    Name of the Scheduled Task to remove.

.PARAMETER TaskPath
    Optional task folder path (e.g. '\MyTasks\').  Defaults to the root '\'.

.PARAMETER RevokeBatchLogonRight
    If specified, also revokes SeBatchLogonRight from the account named by -GmsaAccount.
    Requires -GmsaAccount and an elevated session.

.PARAMETER GmsaAccount
    The gMSA whose batch logon right should be revoked, in DOMAIN\name$ form.  The trailing
    "$" is added automatically if omitted.  Required only when -RevokeBatchLogonRight is used.

.PARAMETER PassThru
    If specified, emits a result object describing what was removed/revoked.

.EXAMPLE
    .\Remove-GmsaScheduledTask.ps1 -TaskName 'NightlyExport'

    Unregisters the 'NightlyExport' task.  Leaves the batch logon right in place.

.EXAMPLE
    .\Remove-GmsaScheduledTask.ps1 -TaskName 'NightlyExport' -RevokeBatchLogonRight `
        -GmsaAccount 'CONTOSO\svc-export$'

    Unregisters the task and revokes SeBatchLogonRight from the gMSA.

.EXAMPLE
    .\Remove-GmsaScheduledTask.ps1 -TaskName 'NightlyExport' -WhatIf

    Shows what would be removed without making changes.

.NOTES
    Author : Hannah Vernon
    Run elevated on the host that runs the task.  Revoking the batch logon right affects every
    task or service that logs on as a batch job under that account on this host - use with care.

.LINK
    https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $TaskName,

    [Parameter()]
    [string] $TaskPath = '\',

    [Parameter()]
    [switch] $RevokeBatchLogonRight,

    [Parameter()]
    [string] $GmsaAccount,

    [Parameter()]
    [switch] $PassThru
)

begin
{
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function Test-IsElevated
    {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function ConvertTo-GmsaFullName
    {
        param ([string] $Account)

        $domain = $null
        $name   = $Account

        if ($Account -match '\\')
        {
            $split  = $Account -split '\\', 2
            $domain = $split[0]
            $name   = $split[1]
        }

        if (-not $name.EndsWith('$'))
        {
            $name = $name + '$'
        }

        if ($domain) { return "$domain\$name" } else { return $name }
    }

    function Revoke-BatchLogonRight
    {
        <#
            Removes SeBatchLogonRight from the supplied account by exporting the local security
            policy with secedit, stripping the account SID from the assignment, and re-importing.
        #>
        param ([Parameter(Mandatory = $true)][string] $AccountName)

        if (-not (Test-IsElevated))
        {
            throw 'Revoking the batch logon right requires an elevated (Administrator) session.'
        }

        $sid = (New-Object System.Security.Principal.NTAccount($AccountName)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value

        $tempDir = [System.IO.Path]::GetTempPath()
        $infPath = Join-Path $tempDir ('secpol_{0}.inf' -f ([guid]::NewGuid().ToString('N')))
        $dbPath  = Join-Path $tempDir ('secpol_{0}.sdb' -f ([guid]::NewGuid().ToString('N')))
        $logPath = Join-Path $tempDir ('secpol_{0}.log' -f ([guid]::NewGuid().ToString('N')))

        try
        {
            & secedit.exe /export /cfg $infPath /areas USER_RIGHTS | Out-Null

            $content = Get-Content -LiteralPath $infPath
            $line    = $content | Where-Object { $_ -match '^SeBatchLogonRight' }

            if (-not $line -or ($line -notmatch [regex]::Escape("*$sid")))
            {
                Write-Verbose "Account does not hold SeBatchLogonRight on this host; nothing to revoke."
                return $false
            }

            # Parse "SeBatchLogonRight = *S-1-...,*S-1-..." and drop the target SID.
            $parts  = ($line -split '=', 2)[1]
            $values = $parts.Split(',') |
                        ForEach-Object { $_.Trim() } |
                        Where-Object { $_ -and ($_ -ne "*$sid") }

            if ($values.Count -gt 0)
            {
                $newLine = 'SeBatchLogonRight = ' + ($values -join ',')
            }
            else
            {
                # Empty assignment list clears the right.
                $newLine = 'SeBatchLogonRight ='
            }

            $content = $content -replace [regex]::Escape($line), $newLine
            Set-Content -LiteralPath $infPath -Value $content -Encoding Unicode

            & secedit.exe /configure /db $dbPath /cfg $infPath /areas USER_RIGHTS /log $logPath | Out-Null
            Write-Verbose "Revoked SeBatchLogonRight from $AccountName ($sid)."
            return $true
        }
        finally
        {
            foreach ($f in @($infPath, $dbPath, $logPath))
            {
                if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

process
{
    if (-not (Test-IsElevated))
    {
        Write-Warning 'This script is not running elevated. Unregistering a Scheduled Task and revoking user rights typically require Administrator privileges.'
    }

    if ($RevokeBatchLogonRight -and -not $GmsaAccount)
    {
        throw '-RevokeBatchLogonRight requires -GmsaAccount.'
    }

    $taskRemoved   = $false
    $rightRevoked  = $false

    # --- Remove the Scheduled Task ------------------------------------------------------
    $existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($existing)
    {
        if ($PSCmdlet.ShouldProcess("$TaskPath$TaskName", 'Unregister Scheduled Task'))
        {
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
            $taskRemoved = $true
            Write-Verbose "Scheduled Task '$TaskName' removed."
        }
    }
    else
    {
        Write-Warning "Scheduled Task '$TaskName' was not found at path '$TaskPath'; nothing to remove."
    }

    # --- Optionally revoke the batch logon right ----------------------------------------
    if ($RevokeBatchLogonRight)
    {
        $full = ConvertTo-GmsaFullName -Account $GmsaAccount
        if ($PSCmdlet.ShouldProcess($full, 'Revoke "Log on as a batch job" (SeBatchLogonRight)'))
        {
            $rightRevoked = Revoke-BatchLogonRight -AccountName $full
        }
    }

    if ($PassThru)
    {
        return [pscustomobject]@{
            TaskName             = $TaskName
            TaskPath             = $TaskPath
            TaskRemoved          = $taskRemoved
            BatchLogonRevoked    = $rightRevoked
            GmsaAccount          = if ($RevokeBatchLogonRight) { ConvertTo-GmsaFullName -Account $GmsaAccount } else { $null }
        }
    }
}
