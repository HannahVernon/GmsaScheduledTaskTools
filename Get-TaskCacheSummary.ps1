<#
.SYNOPSIS
    Compares the three TaskCache sources (registry Tree, registry Tasks, on-disk XML) and
    reports the counts, so you can tell genuine TaskCache corruption from a false alarm.

.DESCRIPTION
    A quick, read-only companion to Test-ScheduledTaskHealth.ps1.  It answers one question that
    determines how to treat a large batch of "OrphanTreeEntry" findings: are the
    TaskCache\Tasks\{GUID} keys actually missing, or did something just fail to enumerate them?

    It counts and cross-references three sources without calling the Task Scheduler service:

      * Tree task nodes   - entries under TaskCache\Tree that have an "Id" value (the GUID).
      * Tasks GUID keys    - subkeys under TaskCache\Tasks.
      * XML task files     - files under %SystemRoot%\System32\Tasks.

    It then reports how many Tree nodes have no matching Tasks key (would-be OrphanTreeEntry),
    how many Tasks keys have no Tree node (would-be OrphanTaskEntry), and an Assessment that
    interprets the numbers.  Optionally it spot-checks specific GUIDs with Test-Path so you can
    confirm directly whether a flagged "orphan" really lacks its Tasks key.

    Run elevated: the TaskCache registry and the Tasks folder are readable only by
    administrators.  This script does not modify anything.

    Interpretation:
      * Tasks GUID keys roughly equal to Tree task nodes, and spot-checks return Exists=True:
        the orphan findings are false; do not repair, and report the numbers.
      * Tasks GUID keys far fewer than Tree task nodes, and spot-checks return Exists=False:
        TaskCache is genuinely damaged.  Prefer System Restore or
        DISM /Online /Cleanup-Image /RestoreHealth and sfc /scannow over mass deletion of Tree
        entries (deleting a Tree entry discards the task definition).

.PARAMETER TaskCacheRegPath
    Registry path to the TaskCache key.  Defaults to
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'.

.PARAMETER TasksPath
    Path to the on-disk task folder.  Defaults to "$env:SystemRoot\System32\Tasks".

.PARAMETER CheckGuid
    One or more task GUIDs (with or without braces) to spot-check directly.  For each, the
    script reports whether TaskCache\Tasks\{GUID} exists and whether a Tree node references it.

.EXAMPLE
    .\Get-TaskCacheSummary.ps1

    Prints the three counts, the cross-reference totals, and an assessment.

.EXAMPLE
    .\Get-TaskCacheSummary.ps1 -CheckGuid '{31C5D67F-4872-4930-9927-901B20E3A4D3}',
        '{0EAC8176-4A3B-454A-AEA7-B19989687099}' | Format-List

    Confirms directly whether two GUIDs that Test-ScheduledTaskHealth flagged as orphaned really
    have no Tasks key.

.NOTES
    Author : Hannah Vernon
    Read-only.  Run elevated.  Use this before repairing a large batch of OrphanTreeEntry
    findings to confirm the damage is real.

.LINK
    https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-start-page
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param (
    [Parameter()]
    [string] $TaskCacheRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache',

    [Parameter()]
    [string] $TasksPath = (Join-Path $env:SystemRoot 'System32\Tasks'),

    [Parameter()]
    [string[]] $CheckGuid
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

    function Format-Guid
    {
        # Extract the canonical GUID (8-4-4-4-12 hex) and return it brace-wrapped and upper.
        # Using a regex match discards any stray surrounding or embedded characters - e.g. a
        # zero-width space or other ignorable character that some TaskCache "Id" values carry -
        # which a Trim-based approach leaves in place and which then breaks ordinal string
        # comparison (the registry and culture-aware comparisons ignore such characters).
        param ([string] $Value)
        $m = [regex]::Match("$Value", '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')
        if ($m.Success) { return ('{' + $m.Value.ToUpperInvariant() + '}') }
        return ("$Value".Trim())
    }
}

process
{
    if (-not (Test-IsElevated))
    {
        Write-Warning 'Not running elevated. The TaskCache registry and the Tasks folder are readable only by administrators; counts may be incomplete. Re-run from an elevated prompt.'
    }

    $treeRegPath  = Join-Path $TaskCacheRegPath 'Tree'
    $tasksRegPath = Join-Path $TaskCacheRegPath 'Tasks'

    # --- Tree task nodes (GUID -> path) -------------------------------------------------
    try
    {
        $treeRoot = Get-Item -LiteralPath $treeRegPath -ErrorAction Stop
    }
    catch
    {
        throw ("Cannot read the TaskCache Tree key at '$treeRegPath': $($_.Exception.Message). " +
               "Run this script from an elevated prompt.")
    }
    $treeRootName = $treeRoot.Name

    $treeGuids = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($key in (Get-ChildItem -LiteralPath $treeRegPath -Recurse -ErrorAction SilentlyContinue))
    {
        try
        {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ($props.PSObject.Properties['Id'] -and $props.Id)
            {
                [void]$treeGuids.Add((Format-Guid $props.Id))
            }
        }
        catch { }
    }

    # --- Tasks GUID keys ----------------------------------------------------------------
    $tasksGuids = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $tasksRegPath)
    {
        foreach ($tk in (Get-ChildItem -LiteralPath $tasksRegPath -ErrorAction SilentlyContinue))
        {
            [void]$tasksGuids.Add((Format-Guid $tk.PSChildName))
        }
    }

    # --- XML files ----------------------------------------------------------------------
    $fileCount = 0
    if (Test-Path -LiteralPath $TasksPath)
    {
        $fileCount = @(Get-ChildItem -LiteralPath $TasksPath -Recurse -File -ErrorAction SilentlyContinue).Count
    }

    # --- Cross-reference ----------------------------------------------------------------
    $treeWithoutTasks = 0
    foreach ($g in $treeGuids) { if (-not $tasksGuids.Contains($g)) { $treeWithoutTasks++ } }
    $tasksWithoutTree = 0
    foreach ($g in $tasksGuids) { if (-not $treeGuids.Contains($g)) { $tasksWithoutTree++ } }

    # --- Assessment ---------------------------------------------------------------------
    $assessment =
        if ($treeGuids.Count -eq 0)
        {
            'No Tree task nodes found - verify -TaskCacheRegPath and that you are elevated.'
        }
        elseif ($tasksGuids.Count -ge ($treeGuids.Count * 0.9))
        {
            'Tasks and Tree counts are close. A large batch of OrphanTreeEntry findings would be suspicious - spot-check with -CheckGuid before repairing.'
        }
        elseif ($tasksGuids.Count -lt ($treeGuids.Count * 0.5))
        {
            'TaskCache\Tasks has far fewer entries than Tree references. If -CheckGuid confirms the keys are genuinely absent, this is real TaskCache damage - prefer System Restore / DISM RestoreHealth + sfc over mass deletion. If the keys actually exist, the enumeration is incomplete - do not repair.'
        }
        else
        {
            'Tasks is somewhat smaller than Tree. Spot-check specific GUIDs with -CheckGuid before deciding to repair.'
        }

    [pscustomobject]@{
        Type             = 'Summary'
        TreeTaskNodes    = $treeGuids.Count
        TasksGuidKeys    = $tasksGuids.Count
        XmlFiles         = $fileCount
        TreeWithoutTasks = $treeWithoutTasks   # would-be OrphanTreeEntry
        TasksWithoutTree = $tasksWithoutTree   # would-be OrphanTaskEntry
        Elevated         = (Test-IsElevated)
        Assessment       = $assessment
    }

    # --- Optional spot-checks -----------------------------------------------------------
    foreach ($raw in @($CheckGuid))
    {
        if (-not $raw) { continue }
        $g = Format-Guid $raw
        $tasksKeyPath = Join-Path $tasksRegPath $g
        [pscustomobject]@{
            Type              = 'SpotCheck'
            Guid              = $g
            TasksKeyExists    = (Test-Path -LiteralPath $tasksKeyPath)
            ReferencedInTree  = $treeGuids.Contains($g)
            TasksKeyPath      = $tasksKeyPath
        }
    }
}
