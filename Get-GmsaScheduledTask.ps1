<#
.SYNOPSIS
    Reports the current principal, action, trigger, and gMSA status of one or more Scheduled
    Tasks.

.DESCRIPTION
    Companion to New-GmsaScheduledTask.ps1 / Remove-GmsaScheduledTask.ps1.  Inspects registered
    Scheduled Tasks on the local host and returns a normalized object describing how each task
    runs, with a focus on the details that matter for gMSA-backed tasks:

      * Principal: the UserId, LogonType, and RunLevel.
      * IsGmsa: a best-effort flag that is $true when the principal looks like a (group)
        managed service account (UserId ends with "$" and LogonType is Password).
      * Action(s): Execute / Arguments / WorkingDirectory.
      * Trigger(s): a human-readable summary of each trigger.
      * State and last/next run info from the task's runtime status.
      * GmsaInstalled: when -TestGmsa is supplied and the principal is a gMSA, the result of
        Test-ADServiceAccount for that account on this host (else $null).

    The objects are pipeline-friendly; use Format-List or Select-Object to shape output, or
    -PassThruTask to also emit the raw CIM task object for further processing.

.PARAMETER TaskName
    One or more task names to report on.  Wildcards are supported (e.g. 'Nightly*').  If
    omitted, all tasks under -TaskPath are returned.

.PARAMETER TaskPath
    Task folder path to search (e.g. '\MyTasks\').  Defaults to '\'.  Combine with
    -Recurse to include subfolders.

.PARAMETER Recurse
    If specified, includes tasks in subfolders of -TaskPath.

.PARAMETER GmsaOnly
    If specified, returns only tasks whose principal looks like a gMSA (see IsGmsa).

.PARAMETER TestGmsa
    If specified, runs Test-ADServiceAccount for each gMSA principal to report whether the
    account is installed and usable on this host.  Requires the RSAT ActiveDirectory module.

.PARAMETER IncludeRunInfo
    If specified, also reports LastRunTime, LastTaskResult, and NextRunTime by calling
    Get-ScheduledTaskInfo for each task.  This is OFF by default because that cmdlet issues a
    separate RPC to the Task Scheduler service per task, and a single legacy or corrupt task
    can make the call block for a long time (or appear to hang).  When enabled, each call is
    bounded by -RunInfoTimeoutSeconds so one bad task cannot stall the whole run.

.PARAMETER RunInfoTimeoutSeconds
    Per-task timeout, in seconds, for the Get-ScheduledTaskInfo call made when -IncludeRunInfo
    is supplied.  If a task exceeds this, its run-info fields are returned as $null and a
    warning is emitted.  Default 10.

.PARAMETER PassThruTask
    If specified, includes the raw ScheduledTask CIM object on each result as a 'Task'
    property.

.EXAMPLE
    .\Get-GmsaScheduledTask.ps1 -TaskName 'NightlyExport' | Format-List

    Shows the full principal, action, and trigger details for one task.

.EXAMPLE
    .\Get-GmsaScheduledTask.ps1 -GmsaOnly -Recurse -TestGmsa |
        Select-Object TaskName, UserId, RunLevel, TriggerSummary, GmsaInstalled

    Lists every gMSA-backed task on the host (all folders) and whether each gMSA is installed.

.EXAMPLE
    .\Get-GmsaScheduledTask.ps1 -TaskName 'Nightly*'

    Reports on all tasks whose name starts with 'Nightly'.

.NOTES
    Author : Hannah Vernon
    Read-only: this script does not modify tasks or user rights.  -TestGmsa requires the
    ActiveDirectory module (RSAT); without it, GmsaInstalled is reported as $null with a
    warning.  Run-info fields (LastRunTime / LastTaskResult / NextRunTime) are populated only
    when -IncludeRunInfo is supplied, because Get-ScheduledTaskInfo can be slow or block on
    hosts with many or corrupt tasks.

.LINK
    https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param (
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [SupportsWildcards()]
    [string[]] $TaskName,

    [Parameter()]
    [string] $TaskPath = '\',

    [Parameter()]
    [switch] $Recurse,

    [Parameter()]
    [switch] $GmsaOnly,

    [Parameter()]
    [switch] $TestGmsa,

    [Parameter()]
    [switch] $IncludeRunInfo,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $RunInfoTimeoutSeconds = 10,

    [Parameter()]
    [switch] $PassThruTask
)

begin
{
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Cache Test-ADServiceAccount results so repeated principals are only tested once.
    $gmsaTestCache = @{}
    $adModuleChecked  = $false
    $adModulePresent  = $false

    function Test-LooksLikeGmsa
    {
        param ($Principal)

        if ($null -eq $Principal -or [string]::IsNullOrEmpty($Principal.UserId))
        {
            return $false
        }

        $user      = $Principal.UserId.Trim()
        $logonType = "$($Principal.LogonType)"

        # gMSA principals are referenced with a trailing '$' and run with LogonType Password.
        return ($user.EndsWith('$') -and $logonType -eq 'Password')
    }

    function Get-BareSamName
    {
        param ([string] $UserId)

        if ([string]::IsNullOrEmpty($UserId)) { return $null }
        return $UserId.Trim().TrimStart('\').Split('\')[-1].TrimEnd('$')
    }

    function ConvertTo-TriggerSummary
    {
        <#
            Produces a short human-readable description of a single trigger CIM instance,
            covering the trigger kinds this script family creates.
        #>
        param ($Trigger)

        if ($null -eq $Trigger) { return $null }

        $type = $Trigger.CimClass.CimClassName   # e.g. MSFT_TaskDailyTrigger

        $tod = $null
        if ($Trigger.StartBoundary)
        {
            try   { $tod = ([datetime]$Trigger.StartBoundary).ToString('yyyy-MM-dd HH:mm:ss') }
            catch { $tod = "$($Trigger.StartBoundary)" }
        }

        $getProp = {
            param($name)
            $p = $Trigger.PSObject.Properties[$name]
            if ($p) { return $p.Value } else { return $null }
        }

        switch ($type)
        {
            'MSFT_TaskDailyTrigger'
            {
                $interval = & $getProp 'DaysInterval'
                $every    = if ($interval -and $interval -gt 1) { "every $interval days" } else { 'daily' }
                return "Daily ($every) at $tod"
            }
            'MSFT_TaskWeeklyTrigger'
            {
                $weeks = & $getProp 'WeeksInterval'
                $days  = & $getProp 'DaysOfWeek'
                $dayText = if ($null -ne $days) { "days bitmask=$days" } else { '' }
                $every   = if ($weeks -and $weeks -gt 1) { "every $weeks weeks" } else { 'weekly' }
                return ("Weekly ($every) $dayText at $tod").Trim()
            }
            'MSFT_TaskTimeTrigger'
            {
                return "Once at $tod"
            }
            'MSFT_TaskBootTrigger'
            {
                return 'At system startup'
            }
            'MSFT_TaskLogonTrigger'
            {
                $u = & $getProp 'UserId'
                if ($u) { return "At logon of $u" } else { return 'At logon (any user)' }
            }
            default
            {
                $base = $type -replace '^MSFT_Task', '' -replace 'Trigger$', ''
                if ($tod) { return "$base at $tod" } else { return $base }
            }
        }
    }

    function Test-GmsaCached
    {
        param ([string] $BareSam)

        if ([string]::IsNullOrEmpty($BareSam)) { return $null }

        if (-not $script:adModuleChecked)
        {
            $script:adModulePresent = [bool](Get-Command -Name Test-ADServiceAccount -ErrorAction SilentlyContinue)
            $script:adModuleChecked = $true
            if (-not $script:adModulePresent)
            {
                Write-Warning 'Test-ADServiceAccount is unavailable (RSAT ActiveDirectory module not installed); GmsaInstalled will be $null.'
            }
        }

        if (-not $script:adModulePresent) { return $null }

        if ($gmsaTestCache.ContainsKey($BareSam))
        {
            return $gmsaTestCache[$BareSam]
        }

        $result = $null
        try
        {
            $result = [bool](Test-ADServiceAccount -Identity $BareSam)
        }
        catch
        {
            Write-Warning "Test-ADServiceAccount failed for '$BareSam': $($_.Exception.Message)"
            $result = $false
        }

        $gmsaTestCache[$BareSam] = $result
        return $result
    }

    function Get-ScheduledTaskInfoSafe
    {
        <#
            Wraps Get-ScheduledTaskInfo in a bounded-time runspace call.  Get-ScheduledTaskInfo
            issues a separate RPC to the Task Scheduler service per task, and a single legacy or
            corrupt task can make that call block indefinitely.  This wrapper abandons the call
            after -TimeoutSeconds and returns $null so enumeration of remaining tasks continues.
        #>
        param (
            [Parameter(Mandatory = $true)][string] $TaskName,
            [Parameter(Mandatory = $true)][string] $TaskPath,
            [Parameter()][int] $TimeoutSeconds = 10
        )

        $ps = [System.Management.Automation.PowerShell]::Create()
        try
        {
            [void]$ps.AddCommand('Get-ScheduledTaskInfo').
                AddParameter('TaskName', $TaskName).
                AddParameter('TaskPath', $TaskPath).
                AddParameter('ErrorAction', 'SilentlyContinue')

            $async = $ps.BeginInvoke()

            if ($async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($TimeoutSeconds)))
            {
                try   { $out = $ps.EndInvoke($async) }
                catch { $out = $null }
                $ps.Dispose()
                if ($out) { return @($out)[0] } else { return $null }
            }
            else
            {
                Write-Warning "Get-ScheduledTaskInfo for '$TaskPath$TaskName' exceeded ${TimeoutSeconds}s; skipping run info for this task."
                # Abandon the hung runspace; do not block the main thread trying to stop/dispose it.
                $null = $ps.BeginStop({ param($r) try { $ps.Dispose() } catch { } }, $null)
                return $null
            }
        }
        catch
        {
            try { $ps.Dispose() } catch { }
            return $null
        }
    }
}

process
{
    # --- Gather the candidate tasks -----------------------------------------------------
    $getParams = @{ ErrorAction = 'SilentlyContinue' }
    if (-not $Recurse)
    {
        $getParams['TaskPath'] = $TaskPath
    }

    $tasks =
        if ($TaskName)
        {
            foreach ($n in $TaskName)
            {
                Get-ScheduledTask -TaskName $n @getParams
            }
        }
        else
        {
            Get-ScheduledTask @getParams
        }

    # When recursing we fetch everything, then filter by the requested path prefix.
    if ($Recurse -and $TaskPath -and $TaskPath -ne '\')
    {
        $prefix = $TaskPath
        if (-not $prefix.EndsWith('\')) { $prefix = $prefix + '\' }
        $tasks = $tasks | Where-Object { $_.TaskPath -like "$prefix*" -or $_.TaskPath -eq $TaskPath }
    }

    $tasks = $tasks | Sort-Object -Property TaskPath, TaskName -Unique

    $taskArray = @($tasks)
    $total     = $taskArray.Count
    $index     = 0
    Write-Verbose "Reporting on $total task(s)."

    foreach ($task in $taskArray)
    {
        $index++
        Write-Progress -Activity 'Inspecting Scheduled Tasks' `
            -Status "$index of $total : $($task.TaskPath)$($task.TaskName)" `
            -PercentComplete $(if ($total -gt 0) { [int](($index / $total) * 100) } else { 0 })

        $principal = $task.Principal
        $isGmsa    = Test-LooksLikeGmsa -Principal $principal

        if ($GmsaOnly -and -not $isGmsa)
        {
            continue
        }

        # --- Actions --------------------------------------------------------------------
        $actions = foreach ($a in @($task.Actions))
        {
            [pscustomobject]@{
                Execute          = $a.Execute
                Arguments        = $a.Arguments
                WorkingDirectory = $a.WorkingDirectory
            }
        }

        # --- Triggers -------------------------------------------------------------------
        $triggerSummaries = foreach ($t in @($task.Triggers))
        {
            ConvertTo-TriggerSummary -Trigger $t
        }
        if (-not $triggerSummaries) { $triggerSummaries = @('(none - run on demand)') }

        # --- gMSA install test ----------------------------------------------------------
        $gmsaInstalled = $null
        $bareSam       = if ($isGmsa) { Get-BareSamName -UserId $principal.UserId } else { $null }
        if ($TestGmsa -and $isGmsa)
        {
            $gmsaInstalled = Test-GmsaCached -BareSam $bareSam
        }

        # --- Runtime info (opt-in; can be slow or hang on some hosts) --------------------
        $info = $null
        if ($IncludeRunInfo)
        {
            $info = Get-ScheduledTaskInfoSafe -TaskName $task.TaskName -TaskPath $task.TaskPath -TimeoutSeconds $RunInfoTimeoutSeconds
        }

        $result = [ordered]@{
            TaskName        = $task.TaskName
            TaskPath        = $task.TaskPath
            State           = "$($task.State)"
            Enabled         = ($task.Settings.Enabled)
            UserId          = $principal.UserId
            LogonType       = "$($principal.LogonType)"
            RunLevel        = "$($principal.RunLevel)"
            IsGmsa          = $isGmsa
            GmsaSamAccount  = $bareSam
            GmsaInstalled   = $gmsaInstalled
            Actions         = $actions
            TriggerSummary  = ($triggerSummaries -join '; ')
            Triggers        = $triggerSummaries
            Description     = $task.Description
            LastRunTime     = if ($info) { $info.LastRunTime }     else { $null }
            LastTaskResult  = if ($info) { $info.LastTaskResult }  else { $null }
            NextRunTime     = if ($info) { $info.NextRunTime }     else { $null }
        }

        if ($PassThruTask)
        {
            $result['Task'] = $task
        }

        [pscustomobject]$result
    }

    Write-Progress -Activity 'Inspecting Scheduled Tasks' -Completed
}
