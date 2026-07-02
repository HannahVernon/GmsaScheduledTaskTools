<#
.SYNOPSIS
    Diagnoses a stalled or unresponsive Windows Task Scheduler by inspecting the on-disk task
    files and the TaskCache registry directly, without calling the Task Scheduler service.

.DESCRIPTION
    When the Task Scheduler service stalls while enumerating tasks, every consumer that goes
    through the service hangs too: the Task Scheduler MMC (taskschd.msc), schtasks.exe, and the
    ScheduledTasks PowerShell module (Get-ScheduledTask / Get-ScheduledTaskInfo).  The usual
    cause is a single damaged or orphaned task definition.

    This script avoids the service entirely.  It reconciles three sources that the service
    expects to agree:

      * The task XML files under %SystemRoot%\System32\Tasks (one file per task).
      * The TaskCache\Tree registry entries (the folder/name hierarchy; each task leaf has an
        "Id" value containing the task's GUID).
      * The TaskCache\Tasks registry subkeys (one {GUID} subkey per task).

    It reports the kinds of inconsistency that commonly make the service hang or fail to load
    a task:

      * OrphanTreeEntry    - a Tree task references a GUID with no TaskCache\Tasks\{GUID} key.
      * OrphanTaskEntry    - a TaskCache\Tasks\{GUID} key that no Tree entry points to.
      * MissingXmlFile     - a Tree task whose XML file is absent on disk.
      * OrphanXmlFile      - an XML file on disk with no corresponding Tree entry.
      * EmptyXmlFile       - a task XML file that is zero bytes.
      * MalformedXml       - a task XML file that does not parse as XML.
      * UnresolvablePrincipal - (only with -ResolvePrincipals) the task's UserId is a SID that
        cannot be translated on this host.
      * ReadError          - a registry key or file that could not be read.

    Reading registry values and files does not call the Task Scheduler service, so this script
    runs even while taskschd.msc is hung.  Run it elevated: the TaskCache registry and the
    Tasks folder are readable only by administrators.

    The script is READ-ONLY.  It does not modify, delete, or repair anything.  Use the
    SuggestedAction on each finding as guidance, and always back up the registry key and XML
    file before removing a damaged task.

    The first object emitted is a Summary record (Category = Summary) that reports the count of
    Tree task nodes, TaskCache\Tasks GUID keys, and on-disk XML files, plus a per-category
    finding tally.  When TaskCache\Tasks holds far fewer entries than the Tree references, a
    warning is raised: a large batch of OrphanTreeEntry findings is either severe TaskCache
    damage or an incomplete enumeration, so verify with Get-TaskCacheSummary.ps1 before
    repairing.

.PARAMETER TasksPath
    Path to the on-disk task folder.  Defaults to "$env:SystemRoot\System32\Tasks".

.PARAMETER TaskCacheRegPath
    Registry path to the TaskCache key.  Defaults to
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'.

.PARAMETER IncludeHealthy
    Also emit an OK record for every task that passes all checks, not just the problems.

.PARAMETER ResolvePrincipals
    Attempt to translate each task's principal SID to an account name and flag any that fail.
    This is OFF by default because translating a domain SID can issue a network lookup that may
    be slow or block on a host with connectivity problems.

.PARAMETER Repair
    Attempt to repair the high-severity findings by backing up and then removing the damaged or
    orphaned task definitions.  This switches the script from read-only to state-changing, so it
    honors -WhatIf and -Confirm (ConfirmImpact is High).  Every item is backed up before removal
    (the registry key is exported and the XML file is copied to -BackupPath).  After a repair,
    reboot so the Task Scheduler service re-reads TaskCache.

    By default only Error-severity categories are repaired: OrphanTreeEntry, OrphanTaskEntry,
    MissingXmlFile, EmptyXmlFile, and MalformedXml.  Use -RepairCategory to narrow that set, and
    -RemoveOrphanXmlFiles to also remove unreferenced (Warning) XML files.

.PARAMETER BackupPath
    Folder to write backups into before any removal.  Defaults to a timestamped folder under
    %TEMP% (ScheduledTaskHealthBackup\yyyyMMdd-HHmmss).  Registry keys are exported as .reg
    files and task XML files are copied preserving their relative path.

.PARAMETER RepairCategory
    Limits -Repair to the named categories.  Valid values: OrphanTreeEntry, OrphanTaskEntry,
    MissingXmlFile, EmptyXmlFile, MalformedXml.  Defaults to all five.

.PARAMETER RemoveOrphanXmlFiles
    When repairing, also remove OrphanXmlFile findings (task XML files on disk with no TaskCache
    entry).  These are Warning-severity and harmless to the service, so they are left alone
    unless this switch is supplied.

.EXAMPLE
    .\Test-ScheduledTaskHealth.ps1 | Format-Table Severity, Category, TaskPath, Detail -Auto

    Lists every detected inconsistency.  Run from an elevated prompt.

.EXAMPLE
    .\Test-ScheduledTaskHealth.ps1 -Repair -WhatIf

    Shows exactly what a repair would back up and remove, without changing anything.

.EXAMPLE
    .\Test-ScheduledTaskHealth.ps1 -Repair -Confirm:$false

    Backs up and removes every damaged/orphaned task, then prompts you to reboot.  Use after
    reviewing a read-only run first.

.EXAMPLE
    .\Test-ScheduledTaskHealth.ps1 | Where-Object Severity -eq 'Error' |
        Select-Object Category, TaskPath, TaskGuid, FilePath, SuggestedAction | Format-List

    Shows only the high-severity findings most likely to be making the service hang, with the
    file and registry locations to investigate.

.EXAMPLE
    .\Test-ScheduledTaskHealth.ps1 -IncludeHealthy |
        Group-Object Severity | Select-Object Name, Count

    Summary of how many tasks are healthy versus how many have problems.

.NOTES
    Author : Hannah Vernon
    By default this is a read-only diagnostic.  With -Repair it becomes state-changing: it backs
    up each damaged or orphaned task (registry export + XML copy to -BackupPath) before removing
    it, and honors -WhatIf / -Confirm.  Run elevated.  Always do a read-only run first, and
    reboot after a repair so the service re-reads TaskCache.

.LINK
    https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-start-page
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
[OutputType([pscustomobject])]
param (
    [Parameter()]
    [string] $TasksPath = (Join-Path $env:SystemRoot 'System32\Tasks'),

    [Parameter()]
    [string] $TaskCacheRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache',

    [Parameter()]
    [switch] $IncludeHealthy,

    [Parameter()]
    [switch] $ResolvePrincipals,

    [Parameter()]
    [switch] $Repair,

    [Parameter()]
    [string] $BackupPath = (Join-Path $env:TEMP ("ScheduledTaskHealthBackup\{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [Parameter()]
    [ValidateSet('OrphanTreeEntry', 'OrphanTaskEntry', 'MissingXmlFile', 'EmptyXmlFile', 'MalformedXml')]
    [string[]] $RepairCategory = @('OrphanTreeEntry', 'OrphanTaskEntry', 'MissingXmlFile', 'EmptyXmlFile', 'MalformedXml'),

    [Parameter()]
    [switch] $RemoveOrphanXmlFiles
)

begin
{
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Findings are collected here so that -Repair can act on them after detection completes.
    $script:findings = New-Object System.Collections.Generic.List[object]

    function Test-IsElevated
    {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function New-Finding
    {
        param (
            [string] $Severity,
            [string] $Category,
            [string] $TaskPath,
            [string] $TaskGuid,
            [string] $FilePath,
            [string] $Detail,
            [string] $SuggestedAction
        )

        $obj = [pscustomobject]@{
            Severity        = $Severity
            Category        = $Category
            TaskPath        = $TaskPath
            TaskGuid        = $TaskGuid
            FilePath        = $FilePath
            Detail          = $Detail
            SuggestedAction = $SuggestedAction
            Repaired        = $null
            RepairDetail    = $null
        }
        $script:findings.Add($obj)
    }

    function Format-RegValueLine
    {
        # Render one registry value as a .reg-format line.
        param ([string] $Name, $Kind, $Data)

        $escape = {
            param($s)
            return ($s -replace '\\', '\\' -replace '"', '\"')
        }
        $nameTok = if ([string]::IsNullOrEmpty($Name)) { '@' } else { '"' + (& $escape $Name) + '"' }

        $toHex = {
            param([byte[]]$bytes)
            return (($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ',')
        }

        switch ("$Kind")
        {
            'String'       { return "$nameTok=`"$(& $escape ([string]$Data))`"" }
            'DWord'        { return ("{0}=dword:{1:x8}" -f $nameTok, ([uint32]([int]$Data))) }
            'QWord'        { return ("{0}=hex(b):{1}" -f $nameTok, (& $toHex ([System.BitConverter]::GetBytes([uint64]([long]$Data))))) }
            'Binary'       { return ("{0}=hex:{1}" -f $nameTok, (& $toHex ([byte[]]$Data))) }
            'ExpandString' {
                $bytes = [System.Text.Encoding]::Unicode.GetBytes([string]$Data) + @(0, 0)
                return ("{0}=hex(2):{1}" -f $nameTok, (& $toHex $bytes))
            }
            'MultiString'  {
                $joined = (@($Data) -join "`0") + "`0`0"
                $bytes  = [System.Text.Encoding]::Unicode.GetBytes($joined)
                return ("{0}=hex(7):{1}" -f $nameTok, (& $toHex $bytes))
            }
            default        { return ("{0}=hex:{1}" -f $nameTok, (& $toHex ([byte[]]$Data))) }
        }
    }

    function Write-RegKeyRecursive
    {
        param ($Key, $Builder)

        [void]$Builder.AppendLine("[$($Key.Name)]")
        foreach ($valueName in $Key.GetValueNames())
        {
            $kind = $Key.GetValueKind($valueName)
            $data = $Key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            [void]$Builder.AppendLine((Format-RegValueLine -Name $valueName -Kind $kind -Data $data))
        }
        [void]$Builder.AppendLine('')

        foreach ($subName in $Key.GetSubKeyNames())
        {
            $child = $Key.OpenSubKey($subName)
            if ($child)
            {
                try   { Write-RegKeyRecursive -Key $child -Builder $Builder }
                finally { $child.Close() }
            }
        }
    }

    function Backup-RegistryKey
    {
        # Export a registry key to a .reg file under the backup folder using the .NET registry
        # API (not reg.exe), so it works even where DisableRegistryTools blocks reg.exe.
        # Returns the backup file path, or $null if the key does not exist.
        param ([string] $PsKeyPath, [string] $BackupRoot, [string] $Label)

        if (-not (Test-Path -LiteralPath $PsKeyPath)) { return $null }
        $regDir = Join-Path $BackupRoot 'Registry'
        if (-not (Test-Path -LiteralPath $regDir)) { New-Item -ItemType Directory -Path $regDir -Force | Out-Null }

        $safe = ($Label -replace '[\\/:*?"<>|]', '_').Trim('_')
        if (-not $safe) { $safe = 'key' }
        $outFile = Join-Path $regDir ("{0}.reg" -f $safe)
        $i = 1
        while (Test-Path -LiteralPath $outFile) { $outFile = Join-Path $regDir ("{0}_{1}.reg" -f $safe, $i); $i++ }

        $rootKey = Get-Item -LiteralPath $PsKeyPath -ErrorAction Stop   # Microsoft.Win32.RegistryKey
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('Windows Registry Editor Version 5.00')
        [void]$sb.AppendLine('')
        Write-RegKeyRecursive -Key $rootKey -Builder $sb
        [System.IO.File]::WriteAllText($outFile, $sb.ToString(), [System.Text.Encoding]::Unicode)
        return $outFile
    }

    function Backup-TaskFile
    {
        # Copy a task XML file into the backup folder, preserving its relative path.
        param ([string] $FilePath, [string] $TasksRoot, [string] $BackupRoot)

        if (-not (Test-Path -LiteralPath $FilePath)) { return $null }
        $rel = $FilePath
        if ($FilePath.StartsWith($TasksRoot, [System.StringComparison]::OrdinalIgnoreCase))
        {
            $rel = $FilePath.Substring($TasksRoot.Length).TrimStart('\')
        }
        $dest = Join-Path (Join-Path $BackupRoot 'Tasks') $rel
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        Copy-Item -LiteralPath $FilePath -Destination $dest -Force
        return $dest
    }

    function Get-RelativeTreePath
    {
        # Convert a full registry key name under ...\TaskCache\Tree\... into the task path the
        # service uses (e.g. '\Microsoft\Windows\Foo').
        param ([string] $FullKeyName, [string] $TreeRootKeyName)

        $rel = $FullKeyName.Substring($TreeRootKeyName.Length)
        if (-not $rel.StartsWith('\')) { $rel = '\' + $rel }
        return $rel
    }
}

process
{
    if (-not (Test-IsElevated))
    {
        Write-Warning 'Not running elevated. The TaskCache registry and the Tasks folder are normally readable only by administrators; results may be incomplete. Re-run from an elevated prompt.'
    }

    $treeRegPath  = Join-Path $TaskCacheRegPath 'Tree'
    $tasksRegPath = Join-Path $TaskCacheRegPath 'Tasks'

    if (-not (Test-Path -LiteralPath $treeRegPath))
    {
        throw "TaskCache Tree key not found at '$treeRegPath'. Verify -TaskCacheRegPath."
    }

    # --- 1. Enumerate Tree task nodes (those with an 'Id' value) ------------------------
    try
    {
        $treeRootKey = Get-Item -LiteralPath $treeRegPath -ErrorAction Stop
    }
    catch
    {
        throw ("Cannot read the TaskCache Tree key at '$treeRegPath': $($_.Exception.Message). " +
               "This key is readable only by administrators, so run this script from an elevated prompt.")
    }
    $treeRootName = $treeRootKey.Name   # e.g. HKEY_LOCAL_MACHINE\SOFTWARE\...\TaskCache\Tree

    # GUID -> task path, and the set of task paths seen in the Tree.
    $treeByGuid  = @{}
    $treePaths   = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    $treeTasks   = New-Object System.Collections.Generic.List[object]

    $treeKeys = Get-ChildItem -LiteralPath $treeRegPath -Recurse -ErrorAction SilentlyContinue
    foreach ($key in $treeKeys)
    {
        $id = $null
        try
        {
            $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ($props.PSObject.Properties['Id']) { $id = $props.Id }
        }
        catch
        {
            New-Finding -Severity 'Warning' -Category 'ReadError' `
                -TaskPath (Get-RelativeTreePath -FullKeyName $key.Name -TreeRootKeyName $treeRootName) `
                -Detail "Could not read Tree key: $($_.Exception.Message)" `
                -SuggestedAction 'Check permissions on the registry key; run elevated.'
            continue
        }

        if (-not $id) { continue }   # this is a folder node, not a task

        $relPath = Get-RelativeTreePath -FullKeyName $key.Name -TreeRootKeyName $treeRootName
        $guid    = "$id".Trim()
        [void]$treePaths.Add($relPath)
        $treeByGuid[$guid] = $relPath
        $treeTasks.Add([pscustomobject]@{ Guid = $guid; Path = $relPath })
    }

    # --- 2. Enumerate TaskCache\Tasks {GUID} subkeys ------------------------------------
    $tasksGuids = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $tasksRegPath)
    {
        foreach ($tk in (Get-ChildItem -LiteralPath $tasksRegPath -ErrorAction SilentlyContinue))
        {
            $guid = $tk.PSChildName
            [void]$tasksGuids.Add($guid)

            if (-not $treeByGuid.ContainsKey($guid))
            {
                $regPathVal = $null
                try
                {
                    $p = Get-ItemProperty -LiteralPath $tk.PSPath -ErrorAction Stop
                    if ($p.PSObject.Properties['Path']) { $regPathVal = "$($p.Path)" }
                }
                catch { }

                New-Finding -Severity 'Error' -Category 'OrphanTaskEntry' `
                    -TaskPath $regPathVal -TaskGuid $guid `
                    -Detail "TaskCache\Tasks\$guid has no matching Tree entry$(if ($regPathVal) { " (registry Path = '$regPathVal')" })." `
                    -SuggestedAction "Back up and delete the registry subkey '$tasksRegPath\$guid' (and any leftover XML), then reboot."
            }
        }
    }

    # --- 3. Walk on-disk task files -----------------------------------------------------
    $diskRelPaths = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $TasksPath)
    {
        $files = Get-ChildItem -LiteralPath $TasksPath -Recurse -File -ErrorAction SilentlyContinue
        foreach ($file in $files)
        {
            $rel = '\' + $file.FullName.Substring($TasksPath.Length).TrimStart('\')
            [void]$diskRelPaths.Add($rel)

            # Zero-byte file.
            if ($file.Length -eq 0)
            {
                New-Finding -Severity 'Error' -Category 'EmptyXmlFile' `
                    -TaskPath $rel -FilePath $file.FullName `
                    -Detail 'Task definition file is zero bytes.' `
                    -SuggestedAction 'Back up and remove the empty file and its TaskCache entries, then recreate the task.'
                continue
            }

            # Malformed XML and optional principal resolution.
            try
            {
                [xml]$xml = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop

                if ($ResolvePrincipals)
                {
                    $userIds = @()
                    try
                    {
                        if ($xml.Task -and $xml.Task.Principals -and $xml.Task.Principals.Principal)
                        {
                            $userIds = @($xml.Task.Principals.Principal) |
                                ForEach-Object { if ($_.PSObject.Properties['UserId']) { "$($_.UserId)" } } |
                                Where-Object { $_ }
                        }
                    }
                    catch { $userIds = @() }

                    foreach ($uid in $userIds)
                    {
                        if ($uid -match '^S-1-')
                        {
                            try
                            {
                                $null = (New-Object System.Security.Principal.SecurityIdentifier($uid)).Translate(
                                    [System.Security.Principal.NTAccount]).Value
                            }
                            catch
                            {
                                New-Finding -Severity 'Warning' -Category 'UnresolvablePrincipal' `
                                    -TaskPath $rel -FilePath $file.FullName `
                                    -Detail "Principal SID '$uid' could not be resolved on this host." `
                                    -SuggestedAction 'Confirm the account still exists; an orphaned SID can prevent the task from loading.'
                            }
                        }
                    }
                }
            }
            catch
            {
                New-Finding -Severity 'Error' -Category 'MalformedXml' `
                    -TaskPath $rel -FilePath $file.FullName `
                    -Detail "Task definition file is not valid XML: $($_.Exception.Message)" `
                    -SuggestedAction 'Back up and remove the corrupt file and its TaskCache entries, then recreate the task. This is a common cause of a hung Task Scheduler.'
            }
        }
    }
    else
    {
        New-Finding -Severity 'Warning' -Category 'ReadError' `
            -FilePath $TasksPath `
            -Detail "Tasks folder not found or inaccessible at '$TasksPath'." `
            -SuggestedAction 'Verify the path and run elevated.'
    }

    # --- 4. Cross-reference: Tree task -> Tasks GUID and -> disk file --------------------
    foreach ($t in $treeTasks)
    {
        $healthy = $true

        if (-not $tasksGuids.Contains($t.Guid))
        {
            $healthy = $false
            New-Finding -Severity 'Error' -Category 'OrphanTreeEntry' `
                -TaskPath $t.Path -TaskGuid $t.Guid `
                -Detail "Tree entry references GUID $($t.Guid) but TaskCache\Tasks\$($t.Guid) does not exist." `
                -SuggestedAction "Back up and delete the Tree entry under '$treeRegPath$($t.Path)', then reboot."
        }

        $expectedFile = Join-Path $TasksPath ($t.Path.TrimStart('\'))
        if (-not (Test-Path -LiteralPath $expectedFile))
        {
            $healthy = $false
            New-Finding -Severity 'Error' -Category 'MissingXmlFile' `
                -TaskPath $t.Path -TaskGuid $t.Guid -FilePath $expectedFile `
                -Detail 'Tree entry has no matching task XML file on disk.' `
                -SuggestedAction 'Back up and remove the dangling TaskCache entries (Tree + Tasks GUID), then reboot.'
        }

        if ($healthy -and $IncludeHealthy)
        {
            New-Finding -Severity 'OK' -Category 'Healthy' `
                -TaskPath $t.Path -TaskGuid $t.Guid -FilePath $expectedFile `
                -Detail 'Tree, Tasks GUID, and XML file are consistent.' `
                -SuggestedAction ''
        }
    }

    # --- 5. Orphan XML files (on disk, not referenced by any Tree entry) -----------------
    foreach ($rel in $diskRelPaths)
    {
        if (-not $treePaths.Contains($rel))
        {
            New-Finding -Severity 'Warning' -Category 'OrphanXmlFile' `
                -TaskPath $rel -FilePath (Join-Path $TasksPath $rel.TrimStart('\')) `
                -Detail 'Task XML file on disk has no corresponding TaskCache\Tree entry.' `
                -SuggestedAction 'The service ignores unreferenced files; remove it after backing up if it is not needed.'
        }
    }

    # --- 6. Optional repair -------------------------------------------------------------
    if ($Repair)
    {
        # Reverse map: task path -> GUID, so file-based findings can locate their TaskCache GUID.
        $guidByPath = @{}
        foreach ($entry in $treeByGuid.GetEnumerator())
        {
            $guidByPath[$entry.Value] = $entry.Key
        }

        $repairCategories = New-Object System.Collections.Generic.List[string]
        $RepairCategory | ForEach-Object { [void]$repairCategories.Add($_) }
        if ($RemoveOrphanXmlFiles) { [void]$repairCategories.Add('OrphanXmlFile') }

        $targets = $script:findings | Where-Object { $repairCategories -contains $_.Category }

        if ($targets)
        {
            if (-not (Test-Path -LiteralPath $BackupPath))
            {
                New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
            }
            Write-Verbose "Repairing $(@($targets).Count) finding(s); backups in '$BackupPath'."
        }

        foreach ($f in $targets)
        {
            # Determine the registry key(s) and file to remove for this finding.
            $treeKeyPs  = if ($f.TaskPath) { ($treeRegPath + $f.TaskPath) } else { $null }
            $guid       = $f.TaskGuid
            if (-not $guid -and $f.TaskPath -and $guidByPath.ContainsKey($f.TaskPath))
            {
                $guid = $guidByPath[$f.TaskPath]
            }
            $tasksKeyPs = if ($guid) { (Join-Path $tasksRegPath $guid) } else { $null }
            $filePath   = $f.FilePath

            $label = ("{0}_{1}" -f $f.Category, ($f.TaskPath -replace '[\\/:*?"<>|]', '_')).Trim('_')
            $what  = "Back up and remove $($f.Category) '$($f.TaskPath)'"
            if ($guid) { $what += " (GUID $guid)" }

            if (-not $PSCmdlet.ShouldProcess($what, 'Repair'))
            {
                $f.Repaired = $false
                $f.RepairDetail = 'Skipped (WhatIf/declined).'
                continue
            }

            try
            {
                $removed = New-Object System.Collections.Generic.List[string]

                # Tree key (for OrphanTreeEntry / MissingXmlFile / file-based with a Tree entry).
                if ($f.Category -in 'OrphanTreeEntry', 'MissingXmlFile' -or
                    ($f.Category -in 'EmptyXmlFile', 'MalformedXml' -and $treeKeyPs -and (Test-Path -LiteralPath $treeKeyPs)))
                {
                    if ($treeKeyPs -and (Test-Path -LiteralPath $treeKeyPs))
                    {
                        Backup-RegistryKey -PsKeyPath $treeKeyPs -BackupRoot $BackupPath -Label ("Tree_$label") | Out-Null
                        Remove-Item -LiteralPath $treeKeyPs -Recurse -Force
                        $removed.Add('Tree entry')
                    }
                }

                # Tasks\{GUID} key (for OrphanTaskEntry / MissingXmlFile / file-based with a GUID).
                if ($tasksKeyPs -and (Test-Path -LiteralPath $tasksKeyPs))
                {
                    Backup-RegistryKey -PsKeyPath $tasksKeyPs -BackupRoot $BackupPath -Label ("Tasks_$label") | Out-Null
                    Remove-Item -LiteralPath $tasksKeyPs -Recurse -Force
                    $removed.Add('Tasks GUID key')
                }

                # The XML file (for EmptyXmlFile / MalformedXml / OrphanXmlFile).
                if ($filePath -and (Test-Path -LiteralPath $filePath))
                {
                    Backup-TaskFile -FilePath $filePath -TasksRoot $TasksPath -BackupRoot $BackupPath | Out-Null
                    Remove-Item -LiteralPath $filePath -Force
                    $removed.Add('XML file')
                }

                $f.Repaired = $true
                $f.RepairDetail = if ($removed.Count) { "Backed up and removed: $($removed -join ', '). Reboot to refresh the service." }
                                  else { 'Nothing to remove (already absent).' }
            }
            catch
            {
                $f.Repaired = $false
                $f.RepairDetail = "Repair failed: $($_.Exception.Message)"
                Write-Warning "Repair of '$($f.TaskPath)' failed: $($_.Exception.Message)"
            }
        }

        if (@($targets | Where-Object Repaired -eq $true).Count -gt 0)
        {
            Write-Warning 'Repairs were made. Reboot this host so the Task Scheduler service re-reads TaskCache.'
        }
    }

    # --- 7. Summary + emit findings -----------------------------------------------------
    $treeNodeCount  = $treeTasks.Count
    $tasksGuidCount = $tasksGuids.Count
    $fileCount      = $diskRelPaths.Count

    $catCounts = $script:findings | Group-Object Category | Sort-Object Name
    $catText   = ($catCounts | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    if (-not $catText) { $catText = 'none' }

    $detail = ("Tree task nodes={0}; TaskCache\Tasks GUID keys={1}; XML files on disk={2}. Findings by category: {3}." -f `
                $treeNodeCount, $tasksGuidCount, $fileCount, $catText)

    # Heuristic: if Tasks holds far fewer GUID keys than the Tree references, the many
    # OrphanTreeEntry findings are either severe TaskCache damage or an enumeration problem.
    # Either way, verify before mass-repairing.
    $assessment = ''
    $orphanTree = ($script:findings | Where-Object Category -eq 'OrphanTreeEntry' | Measure-Object).Count
    if ($treeNodeCount -gt 0 -and $tasksGuidCount -lt ($treeNodeCount * 0.5) -and $orphanTree -gt 10)
    {
        $assessment = ("TaskCache\Tasks has far fewer entries ($tasksGuidCount) than Tree references ($treeNodeCount), " +
                       "producing $orphanTree OrphanTreeEntry findings. Before repairing, confirm whether those Tasks GUID " +
                       "keys are genuinely missing (run Get-TaskCacheSummary.ps1 / spot-check Test-Path on a few). If they " +
                       "actually exist, do NOT repair. If they are truly missing, prefer System Restore or " +
                       "DISM /Online /Cleanup-Image /RestoreHealth over mass deletion of Tree entries.")
        Write-Warning $assessment
    }

    $summary = [pscustomobject]@{
        Severity        = 'Info'
        Category        = 'Summary'
        TaskPath        = $null
        TaskGuid        = $null
        FilePath        = $null
        Detail          = $detail
        SuggestedAction = $assessment
        Repaired        = $null
        RepairDetail    = $null
    }

    $summary
    foreach ($f in $script:findings)
    {
        $f
    }
}
