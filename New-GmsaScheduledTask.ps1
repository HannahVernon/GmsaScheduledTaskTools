<#
.SYNOPSIS
    Creates a Windows Scheduled Task that runs under a Group Managed Service Account (gMSA).

.DESCRIPTION
    Encapsulates the host-side steps required to register a Scheduled Task that runs as a
    gMSA.  On the machine where it is run, the script can optionally:

      * Verify the gMSA is installed and usable on this host (Test-ADServiceAccount).
      * Grant the gMSA the "Log on as a batch job" (SeBatchLogonRight) user right, which
        is required for a Task Scheduler task to start under that account.
      * Register (or replace) the Scheduled Task with the supplied program, arguments,
        working directory, and trigger.

    The task principal is created with -LogonType Password.  Despite the name, no password
    is supplied: this LogonType instructs Task Scheduler to retrieve the gMSA's managed
    password from Active Directory at run time.  The gMSA account name is referenced with a
    trailing "$" (e.g. CONTOSO\svc-myjob$).

    Requirements / assumptions (see NOTES):
      * Windows Server 2012 or later (gMSA support).
      * A KDS root key exists in the domain and the gMSA has already been created with this
        host listed in PrincipalsAllowedToRetrieveManagedPassword, and installed via
        Install-ADServiceAccount.
      * Run this script elevated (Administrator) on the host that will run the task.

.PARAMETER TaskName
    Name of the Scheduled Task to create.  If a task with this name already exists it is
    replaced (Register-ScheduledTask -Force).

.PARAMETER GmsaAccount
    The gMSA to run the task as, in DOMAIN\name$ form.  The trailing "$" is added
    automatically if omitted.  A bare name (no domain) is also accepted.

.PARAMETER Execute
    The program or script host to launch (e.g. powershell.exe, pwsh.exe, or a path to an
    .exe).

.PARAMETER Argument
    Optional arguments passed to the Execute program (e.g. '-NoProfile -File C:\Scripts\Job.ps1').

.PARAMETER WorkingDirectory
    Optional working directory for the action.

.PARAMETER Description
    Optional free-text description stored on the task.

.PARAMETER TriggerType
    The kind of trigger to create: Daily, Weekly, Once, AtStartup, AtLogon, or None.
    Default is Daily.  Use None to create the task with no trigger (run on demand only).

.PARAMETER At
    The start time (and, for Once, date) of the trigger.  Required for Daily, Weekly, and
    Once.  Accepts any value convertible to [datetime] (e.g. '2:00AM', '2026-07-01 02:00').

.PARAMETER DaysOfWeek
    For Weekly triggers, one or more days the task runs (e.g. Monday, Wednesday).

.PARAMETER DaysInterval
    For Daily triggers, the interval in days between runs.  Default 1.

.PARAMETER WeeksInterval
    For Weekly triggers, the interval in weeks between runs.  Default 1.

.PARAMETER RunLevel
    Privilege level: Limited (default) or Highest (run elevated).

.PARAMETER GrantBatchLogonRight
    If specified, grants the gMSA the "Log on as a batch job" user right on this host before
    registering the task.  Requires elevation.

.PARAMETER SkipGmsaTest
    If specified, skips the Test-ADServiceAccount validation.  Use only when the RSAT
    ActiveDirectory module is unavailable but you are certain the gMSA is installed.

.PARAMETER StartWhenAvailable
    If specified, the task is allowed to start late if a scheduled start was missed.

.PARAMETER Force
    By default the script is idempotent: if a task with the same name already exists and its
    action, principal, and trigger already match the requested configuration, registration is
    skipped and the existing task is returned unchanged.  Specify -Force to always
    (re)register the task regardless of the current state.

.EXAMPLE
    .\New-GmsaScheduledTask.ps1 -TaskName 'NightlyExport' -GmsaAccount 'CONTOSO\svc-export$' `
        -Execute 'powershell.exe' -Argument '-NoProfile -File C:\Scripts\Export.ps1' `
        -TriggerType Daily -At 2:00AM -GrantBatchLogonRight -RunLevel Highest

    Grants the batch logon right, then creates a daily 2 AM task running elevated as the gMSA.

.EXAMPLE
    .\New-GmsaScheduledTask.ps1 -TaskName 'WeeklyReindex' -GmsaAccount 'svc-sql$' `
        -Execute 'sqlcmd.exe' -Argument '-S SQL01 -i C:\Scripts\Reindex.sql' `
        -TriggerType Weekly -DaysOfWeek Sunday -At 1:00AM

    Creates a weekly Sunday 1 AM task.  The domain is inferred for the bare gMSA name.

.EXAMPLE
    .\New-GmsaScheduledTask.ps1 -TaskName 'OnDemandJob' -GmsaAccount 'CONTOSO\svc-job$' `
        -Execute 'powershell.exe' -Argument '-File C:\Scripts\Job.ps1' -TriggerType None

    Creates a run-on-demand task (no trigger) that runs as the gMSA.

.NOTES
    Author : Hannah Vernon
    Run this script elevated on the host that will execute the task.  The gMSA must already
    be created in AD and installed on this host (Install-ADServiceAccount).  The
    "Log on as a batch job" right can be granted with -GrantBatchLogonRight or via Group
    Policy.

.LINK
    https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $TaskName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $GmsaAccount,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Execute,

    [Parameter()]
    [string] $Argument,

    [Parameter()]
    [string] $WorkingDirectory,

    [Parameter()]
    [string] $Description,

    [Parameter()]
    [ValidateSet('Daily', 'Weekly', 'Once', 'AtStartup', 'AtLogon', 'None')]
    [string] $TriggerType = 'Daily',

    [Parameter()]
    [datetime] $At,

    [Parameter()]
    [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
    [string[]] $DaysOfWeek,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int] $DaysInterval = 1,

    [Parameter()]
    [ValidateRange(1, 52)]
    [int] $WeeksInterval = 1,

    [Parameter()]
    [ValidateSet('Limited', 'Highest')]
    [string] $RunLevel = 'Limited',

    [Parameter()]
    [switch] $GrantBatchLogonRight,

    [Parameter()]
    [switch] $SkipGmsaTest,

    [Parameter()]
    [switch] $StartWhenAvailable,

    [Parameter()]
    [switch] $Force
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

    function ConvertTo-GmsaParts
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

        # Ensure the trailing '$' that identifies a (g)MSA logon.
        if (-not $name.EndsWith('$'))
        {
            $name = $name + '$'
        }

        $full = if ($domain) { "$domain\$name" } else { $name }

        return [pscustomobject]@{
            Domain     = $domain
            SamAccount = $name           # e.g. svc-job$
            Full       = $full           # e.g. CONTOSO\svc-job$
            BareSam    = $name.TrimEnd('$')
        }
    }

    function Grant-BatchLogonRight
    {
        <#
            Grants SeBatchLogonRight to the supplied account by exporting the local security
            policy with secedit, appending the account SID, and re-importing it.  This is the
            scriptable equivalent of "Log on as a batch job" under Local Security Policy.
        #>
        param ([Parameter(Mandatory = $true)][string] $AccountName)

        if (-not (Test-IsElevated))
        {
            throw 'Granting the batch logon right requires an elevated (Administrator) session.'
        }

        $sid = (New-Object System.Security.Principal.NTAccount($AccountName)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value

        $tempDir = [System.IO.Path]::GetTempPath()
        $infPath = Join-Path $tempDir ('secpol_{0}.inf' -f ([guid]::NewGuid().ToString('N')))
        $dbPath  = Join-Path $tempDir ('secpol_{0}.sdb' -f ([guid]::NewGuid().ToString('N')))
        $logPath = Join-Path $tempDir ('secpol_{0}.log' -f ([guid]::NewGuid().ToString('N')))

        try
        {
            # Export the current SeBatchLogonRight assignment.
            & secedit.exe /export /cfg $infPath /areas USER_RIGHTS | Out-Null

            $content = Get-Content -LiteralPath $infPath
            $line    = $content | Where-Object { $_ -match '^SeBatchLogonRight' }

            if ($line)
            {
                if ($line -match [regex]::Escape("*$sid"))
                {
                    Write-Verbose "Account already holds SeBatchLogonRight; nothing to do."
                    return
                }

                $newLine = $line.TrimEnd() + ",*$sid"
                $content = $content -replace [regex]::Escape($line), $newLine
            }
            else
            {
                # No existing assignment line; append one under [Privilege Rights].
                $output = New-Object System.Collections.Generic.List[string]
                $added  = $false
                foreach ($c in $content)
                {
                    $output.Add($c)
                    if ($c -match '^\[Privilege Rights\]' -and -not $added)
                    {
                        $output.Add("SeBatchLogonRight = *$sid")
                        $added = $true
                    }
                }
                $content = $output
            }

            Set-Content -LiteralPath $infPath -Value $content -Encoding Unicode

            & secedit.exe /configure /db $dbPath /cfg $infPath /areas USER_RIGHTS /log $logPath | Out-Null
            Write-Verbose "Granted SeBatchLogonRight to $AccountName ($sid)."
        }
        finally
        {
            foreach ($f in @($infPath, $dbPath, $logPath))
            {
                if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    function Get-TriggerSignature
    {
        <#
            Reduces a Scheduled Task trigger CIM instance to a normalized, comparable string
            so a desired trigger can be matched against an already-registered one.  Only the
            fields this script can set are included; the time-of-day portion of StartBoundary
            is compared (not the date) so Daily/Weekly triggers match regardless of the
            registration date.
        #>
        param ($Trigger)

        if ($null -eq $Trigger) { return '<none>' }

        $type = $Trigger.CimClass.CimClassName   # e.g. MSFT_TaskDailyTrigger
        $parts = New-Object System.Collections.Generic.List[string]
        $parts.Add("type=$type")

        $tod = ''
        if ($Trigger.StartBoundary)
        {
            try { $tod = ([datetime]$Trigger.StartBoundary).ToString('HH:mm:ss') } catch { $tod = $Trigger.StartBoundary }
        }
        $parts.Add("tod=$tod")

        foreach ($prop in 'DaysInterval', 'WeeksInterval', 'DaysOfWeek')
        {
            $val = $Trigger.PSObject.Properties[$prop]
            if ($val -and $null -ne $val.Value)
            {
                $parts.Add("$prop=$($val.Value)")
            }
        }

        return ($parts -join ';')
    }

    function Test-TaskMatchesDesired
    {
        <#
            Returns $true when an existing registered task already matches the desired action,
            principal, and trigger configuration.  Used to make registration idempotent.
        #>
        param (
            [Parameter(Mandatory = $true)] $ExistingTask,
            [Parameter(Mandatory = $true)] $DesiredAction,
            [Parameter(Mandatory = $true)] $DesiredPrincipal,
            [Parameter()]                  $DesiredTrigger
        )

        # --- Action ---------------------------------------------------------------------
        $exAction = @($ExistingTask.Actions)[0]
        if ($null -eq $exAction) { return $false }

        $norm = { param($v) if ([string]::IsNullOrEmpty($v)) { '' } else { ([string]$v).Trim() } }

        if ((& $norm $exAction.Execute)          -ne (& $norm $DesiredAction.Execute))          { return $false }
        if ((& $norm $exAction.Arguments)        -ne (& $norm $DesiredAction.Arguments))        { return $false }
        if ((& $norm $exAction.WorkingDirectory) -ne (& $norm $DesiredAction.WorkingDirectory)) { return $false }

        # --- Principal ------------------------------------------------------------------
        $exPrincipal = $ExistingTask.Principal
        # Compare on the SAM portion so DOMAIN\name$ matches name$ etc.
        $exUser  = (& $norm $exPrincipal.UserId).TrimStart('\').Split('\')[-1].TrimEnd('$')
        $desUser = (& $norm $DesiredPrincipal.UserId).TrimStart('\').Split('\')[-1].TrimEnd('$')
        if ($exUser -ne $desUser) { return $false }

        if ("$($exPrincipal.LogonType)" -ne "$($DesiredPrincipal.LogonType)") { return $false }
        if ("$($exPrincipal.RunLevel)"  -ne "$($DesiredPrincipal.RunLevel)")  { return $false }

        # --- Trigger --------------------------------------------------------------------
        $exTriggers  = @($ExistingTask.Triggers)
        $desiredSig  = Get-TriggerSignature -Trigger $DesiredTrigger

        if ($null -eq $DesiredTrigger)
        {
            if ($exTriggers.Count -ne 0) { return $false }
        }
        else
        {
            if ($exTriggers.Count -ne 1) { return $false }
            if ((Get-TriggerSignature -Trigger $exTriggers[0]) -ne $desiredSig) { return $false }
        }

        return $true
    }
}

process
{
    if (-not (Test-IsElevated))
    {
        Write-Warning 'This script is not running elevated. Registering a Scheduled Task and granting user rights typically require Administrator privileges.'
    }

    $gmsa = ConvertTo-GmsaParts -Account $GmsaAccount
    Write-Verbose "Resolved gMSA principal: $($gmsa.Full)"

    # --- Validate the gMSA is installed on this host -----------------------------------
    if (-not $SkipGmsaTest)
    {
        if (Get-Command -Name Test-ADServiceAccount -ErrorAction SilentlyContinue)
        {
            Write-Verbose "Testing gMSA '$($gmsa.BareSam)' with Test-ADServiceAccount..."
            if (-not (Test-ADServiceAccount -Identity $gmsa.BareSam))
            {
                throw ("Test-ADServiceAccount reported that '{0}' is not usable on this host. " +
                       "Confirm the gMSA exists, this computer is in PrincipalsAllowedToRetrieveManagedPassword, " +
                       "and Install-ADServiceAccount has been run." -f $gmsa.BareSam)
            }
            Write-Verbose 'gMSA validation succeeded.'
        }
        else
        {
            Write-Warning ('Test-ADServiceAccount is unavailable (RSAT ActiveDirectory module not installed). ' +
                           'Skipping gMSA validation. Use -SkipGmsaTest to suppress this warning.')
        }
    }

    # --- Grant "Log on as a batch job" if requested ------------------------------------
    if ($GrantBatchLogonRight)
    {
        if ($PSCmdlet.ShouldProcess($gmsa.Full, 'Grant "Log on as a batch job" (SeBatchLogonRight)'))
        {
            Grant-BatchLogonRight -AccountName $gmsa.Full
        }
    }

    # --- Build the action ---------------------------------------------------------------
    $actionParams = @{ Execute = $Execute }
    if ($PSBoundParameters.ContainsKey('Argument') -and $Argument)
    {
        $actionParams['Argument'] = $Argument
    }
    if ($PSBoundParameters.ContainsKey('WorkingDirectory') -and $WorkingDirectory)
    {
        $actionParams['WorkingDirectory'] = $WorkingDirectory
    }
    $action = New-ScheduledTaskAction @actionParams

    # --- Build the trigger --------------------------------------------------------------
    $trigger = $null
    switch ($TriggerType)
    {
        'Daily'
        {
            if (-not $PSBoundParameters.ContainsKey('At'))
            {
                throw "TriggerType 'Daily' requires -At (start time)."
            }
            $trigger = New-ScheduledTaskTrigger -Daily -At $At -DaysInterval $DaysInterval
        }
        'Weekly'
        {
            if (-not $PSBoundParameters.ContainsKey('At'))
            {
                throw "TriggerType 'Weekly' requires -At (start time)."
            }
            if (-not $DaysOfWeek -or $DaysOfWeek.Count -eq 0)
            {
                throw "TriggerType 'Weekly' requires -DaysOfWeek."
            }
            $trigger = New-ScheduledTaskTrigger -Weekly -At $At -DaysOfWeek $DaysOfWeek -WeeksInterval $WeeksInterval
        }
        'Once'
        {
            if (-not $PSBoundParameters.ContainsKey('At'))
            {
                throw "TriggerType 'Once' requires -At (start date/time)."
            }
            $trigger = New-ScheduledTaskTrigger -Once -At $At
        }
        'AtStartup'
        {
            $trigger = New-ScheduledTaskTrigger -AtStartup
        }
        'AtLogon'
        {
            $trigger = New-ScheduledTaskTrigger -AtLogOn
        }
        'None'
        {
            $trigger = $null
        }
    }

    # --- Build the principal (the gMSA) -------------------------------------------------
    # -LogonType Password tells Task Scheduler to fetch the gMSA managed password from AD.
    $principal = New-ScheduledTaskPrincipal -UserId $gmsa.Full -LogonType Password -RunLevel $RunLevel

    # --- Settings -----------------------------------------------------------------------
    $settingsParams = @{}
    if ($StartWhenAvailable)
    {
        $settingsParams['StartWhenAvailable'] = $true
    }
    $settings = New-ScheduledTaskSettingsSet @settingsParams

    # --- Idempotency check --------------------------------------------------------------
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask -and -not $Force)
    {
        if (Test-TaskMatchesDesired -ExistingTask $existingTask -DesiredAction $action `
                -DesiredPrincipal $principal -DesiredTrigger $trigger)
        {
            Write-Verbose "Scheduled Task '$TaskName' already matches the requested configuration; skipping. Use -Force to re-register."
            Write-Information "Scheduled Task '$TaskName' is already up to date; no changes made." -InformationAction Continue
            return $existingTask
        }
        Write-Verbose "Scheduled Task '$TaskName' exists but differs from the requested configuration; updating."
    }

    # --- Register -----------------------------------------------------------------------
    $registerParams = @{
        TaskName  = $TaskName
        Action    = $action
        Principal = $principal
        Settings  = $settings
        Force     = $true
    }
    if ($trigger)
    {
        $registerParams['Trigger'] = $trigger
    }
    if ($PSBoundParameters.ContainsKey('Description') -and $Description)
    {
        $registerParams['Description'] = $Description
    }

    if ($PSCmdlet.ShouldProcess($TaskName, "Register Scheduled Task running as $($gmsa.Full)"))
    {
        $task = Register-ScheduledTask @registerParams
        Write-Verbose "Scheduled Task '$TaskName' registered successfully."
        return $task
    }
}
