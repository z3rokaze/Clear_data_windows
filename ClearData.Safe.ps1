#Requires -Version 5.1
<#
.SYNOPSIS
    ClearData.Safe.ps1 - Safety-first junk / cache / temp cleanup for
    Windows 10/11 and Windows Server 2019/2022/2025.

.DESCRIPTION
    This script removes well-known *safe* junk: temporary files, caches,
    update leftovers, browser cache, delivery optimization cache, recycle bin
    content, thumbnails, crash dumps, archived logs and similar throwaway data.

    It is built around three hard guarantees:

      1. PREVIEW BY DEFAULT
         Nothing is ever deleted unless you explicitly pass -Mode Clean.
         Preview mode only scans, measures and logs what *would* be removed.

      2. ALLOWLIST-ONLY
         The script only ever operates inside a fixed set of known safe
         temp/cache locations. It never performs broad recursive deletion of
         arbitrary paths, and it never deletes the cleanup root folder itself -
         only eligible child items inside it.

      3. DEFENSE IN DEPTH
         Before any item is touched it must pass every safety gate:
         resolved -> exists -> not a dangerous/system root -> not a reparse
         point/junction (leaf AND every ancestor) -> the resolved real target is
         not protected -> inside an allowlisted location -> older than
         -MinimumAgeHours. Locked files are skipped and logged, never forced.

    The script works without Administrator for user-level cleanup. Admin-only
    features (Windows Update cache, Delivery Optimization, DISM, system dumps,
    archived event logs, Prefetch, all-users cleanup) are SKIPPED WITH A WARNING
    when not elevated - never silently.

.PARAMETER Mode
    Preview (default) or Clean.
      Preview - scan and report only. Deletes NOTHING.
      Clean   - actually delete eligible items.

.PARAMETER MinimumAgeHours
    Only items whose LastWriteTime is older than this many hours are eligible.
    Default: 24. Use 0 to make ALL items in allowlisted folders eligible.

.PARAMETER IncludeBrowserCache
    Also clean Chrome / Edge / Brave / Firefox cache subfolders (cache only -
    never cookies, history, passwords, bookmarks or profile data). Also clears
    browser shader and component-updater caches (e.g. component_crx_cache);
    these are re-downloaded automatically on next launch.

.PARAMETER IncludeAllUsersTemp
    Also clean Temp / INetCache / WER / D3DSCache under every user profile.
    Requires Administrator.

.PARAMETER IncludeWindowsUpdateCache
    Clean C:\Windows\SoftwareDistribution\Download. In Clean mode this stops
    the wuauserv + bits services first (and only deletes if they actually
    stopped), then restarts them afterwards. Requires Administrator.

.PARAMETER IncludeDeliveryOptimizationCache
    Clean the Delivery Optimization cache. In Clean mode this stops the dosvc
    service first and restarts it afterwards. Requires Administrator.

.PARAMETER IncludeRecycleBin
    Empty the Recycle Bin (all drives). Clean mode only actually empties it.
    NOTE: the OS empties the bin in full; -MinimumAgeHours does not apply here.

.PARAMETER RunDismComponentCleanup
    Run: DISM.exe /Online /Cleanup-Image /StartComponentCleanup
    Requires Administrator. Does NOT use /ResetBase (which would make installed
    updates non-removable). Clean mode only. Exit code 3010 = success, reboot
    required.

.PARAMETER IncludeCrashDumps
    Clean user CrashDumps, system Minidump (*.dmp) and C:\Windows\MEMORY.DMP.
    WARNING: crash dumps may be useful for debugging.

.PARAMETER IncludeArchivedEventLogs
    Delete ONLY Archive-*.evtx rolled-over event logs in winevt\Logs. Active
    event logs are never touched. Requires Administrator.
    WARNING: archived logs may be useful for security / forensic review.

.PARAMETER IncludeThumbnailAndIconCache
    Delete thumbcache_*.db / iconcache_*.db. Some files may be locked by
    Explorer and will be skipped (logged) - this script does not kill Explorer.

.PARAMETER IncludeDeveloperCaches
    Clean npm / pip / Gradle download caches only. NEVER touches source code,
    node_modules, virtual environments, .git folders, lock files or build
    output. WARNING: cached packages may need to be downloaded again later.
    (The Maven local repository is NOT included here - see -IncludeMavenRepository.)

.PARAMETER IncludeMavenRepository
    Clean ~/.m2/repository. WARNING: this can contain locally-installed
    (mvn install) and SNAPSHOT artifacts that CANNOT be re-downloaded from
    public repositories; deleting it can break offline builds. Opt-in, separate
    from -IncludeDeveloperCaches by design.

.PARAMETER IncludePrefetch
    Clean C:\Windows\Prefetch (*.pf). Requires Administrator. Prefetch is
    auto-regenerated; the next launch of some apps may be slightly slower.

.PARAMETER IncludeAppCaches
    Clean cache subfolders of common Electron apps (Teams, VS Code, Slack,
    Discord) - cache only, never settings/profile data.

.PARAMETER ForceCloseBrowsers
    In Clean mode, close Chrome / Edge / Brave / Firefox before cleaning their
    cache so locked files can be removed. A graceful close is attempted first;
    processes that ignore it are force-terminated (unsaved tabs/forms may be
    lost). Ignored in Preview mode.

.PARAMETER LogPath
    Path to the log file (or a folder). Default: %TEMP%\ClearData_<timestamp>_<pid>.log
    A matching .csv summary report is written next to the log.

.EXAMPLE
    # Preview only (default - deletes nothing):
    powershell -ExecutionPolicy Bypass -File .\ClearData.Safe.ps1

.EXAMPLE
    # Safe cleanup:
    powershell -ExecutionPolicy Bypass -File .\ClearData.Safe.ps1 -Mode Clean

.EXAMPLE
    # Strong safe cleanup as Administrator:
    powershell -ExecutionPolicy Bypass -File .\ClearData.Safe.ps1 -Mode Clean -IncludeBrowserCache -IncludeAllUsersTemp -IncludeWindowsUpdateCache -IncludeDeliveryOptimizationCache -IncludeRecycleBin -RunDismComponentCleanup -IncludeThumbnailAndIconCache

.EXAMPLE
    # Very strong cleanup, still safety-focused:
    powershell -ExecutionPolicy Bypass -File .\ClearData.Safe.ps1 -Mode Clean -IncludeBrowserCache -IncludeAllUsersTemp -IncludeWindowsUpdateCache -IncludeDeliveryOptimizationCache -IncludeRecycleBin -RunDismComponentCleanup -IncludeThumbnailAndIconCache -IncludeCrashDumps -IncludeArchivedEventLogs -IncludeDeveloperCaches

.NOTES
    No network calls. No telemetry. No third-party downloads. No external
    dependencies. Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Clean')]
    [string]$Mode = 'Preview',

    [ValidateRange(0, 2147483647)]
    [int]$MinimumAgeHours = 24,

    [switch]$IncludeBrowserCache,
    [switch]$IncludeAllUsersTemp,
    [switch]$IncludeWindowsUpdateCache,
    [switch]$IncludeDeliveryOptimizationCache,
    [switch]$IncludeRecycleBin,
    [switch]$RunDismComponentCleanup,
    [switch]$IncludeCrashDumps,
    [switch]$IncludeArchivedEventLogs,
    [switch]$IncludeThumbnailAndIconCache,
    [switch]$IncludeDeveloperCaches,
    [switch]$IncludeMavenRepository,
    [switch]$IncludePrefetch,
    [switch]$IncludeAppCaches,
    [switch]$ForceCloseBrowsers,

    [string]$LogPath
)

# We control all error handling explicitly via try/catch and -ErrorAction.
$ErrorActionPreference = 'Continue'
Set-StrictMode -Off

$Script:Version = '1.1.0'

# ----------------------------------------------------------------------------
# Console encoding (best effort - never fatal)
# ----------------------------------------------------------------------------
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
} catch { }

# ============================================================================
#  CORE STATE
# ============================================================================
$Script:IsAdmin         = $false
$Script:LogFile         = $null
$Script:CsvFile         = $null
$Script:LogEncoding     = [System.Text.UTF8Encoding]::new($false)   # UTF-8, no BOM
$Script:Results         = New-Object System.Collections.Generic.List[object]
$Script:Allowlist       = New-Object 'System.Collections.Generic.HashSet[string]'
$Script:Processed       = New-Object 'System.Collections.Generic.HashSet[string]'
$Script:StartTime       = Get-Date
$Script:Cutoff          = $Script:StartTime
$Script:CanResolveLinks = $false

# ============================================================================
#  NATIVE: real-path resolution (junction/symlink target) - PS 5.1 + 7
# ============================================================================
function Initialize-Native {
    $Script:CanResolveLinks = $false
    try {
        if (-not ('ClearDataNative.Native' -as [type])) {
            Add-Type -Namespace 'ClearDataNative' -Name 'Native' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern uint GetFinalPathNameByHandleW(System.IntPtr hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(System.IntPtr hObject);
'@ -ErrorAction Stop
        }
        $Script:CanResolveLinks = $true
    } catch {
        $Script:CanResolveLinks = $false
    }
}

function Resolve-RealPath {
    # Return the canonical on-disk target of $Path (junctions/symlinks fully
    # resolved), or $null if it cannot be resolved.
    param([string]$Path)
    if (-not $Script:CanResolveLinks) { return $null }
    $handle = [IntPtr]::Zero
    try {
        $FILE_SHARE_ALL          = [uint32]7      # READ|WRITE|DELETE
        $OPEN_EXISTING           = [uint32]3
        $FILE_FLAG_BACKUP_SEMANTICS = [uint32]0x02000000   # required to open a directory handle
        $handle = [ClearDataNative.Native]::CreateFileW($Path, [uint32]0, $FILE_SHARE_ALL, [IntPtr]::Zero, $OPEN_EXISTING, $FILE_FLAG_BACKUP_SEMANTICS, [IntPtr]::Zero)
        if ($handle -eq [IntPtr]::Zero -or $handle.ToInt64() -eq -1) { return $null }

        $sb = New-Object System.Text.StringBuilder 1024
        $len = [ClearDataNative.Native]::GetFinalPathNameByHandleW($handle, $sb, [uint32]1024, [uint32]0)
        if ($len -eq 0) { return $null }
        if ($len -gt 1024) {
            $sb = New-Object System.Text.StringBuilder ([int]$len + 1)
            $len = [ClearDataNative.Native]::GetFinalPathNameByHandleW($handle, $sb, [uint32]($len + 1), [uint32]0)
            if ($len -eq 0) { return $null }
        }
        $result = $sb.ToString()
        if ($result.StartsWith('\\?\UNC\')) { $result = '\\' + $result.Substring(8) }
        elseif ($result.StartsWith('\\?\')) { $result = $result.Substring(4) }
        return $result
    } catch {
        return $null
    } finally {
        if ($handle -ne [IntPtr]::Zero -and $handle.ToInt64() -ne -1) {
            try { [void][ClearDataNative.Native]::CloseHandle($handle) } catch { }
        }
    }
}

# ============================================================================
#  LOW-LEVEL HELPERS
# ============================================================================

function Get-NormalizedPath {
    # Canonical, comparable form: full path, no trailing separator, lower-case.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Path)
        $full = [System.IO.Path]::GetFullPath($expanded)
        # Canonicalize a drive root (e.g. "C:\") to "c:" WITHOUT stripping the
        # backslash first - "C:".TrimEnd('\') would otherwise become drive-
        # relative and be re-resolved to the current directory by GetFullPath.
        if ($full -match '^[A-Za-z]:\\?$') { return $full.Substring(0, 2).ToLowerInvariant() }
        return $full.TrimEnd('\', '/').ToLowerInvariant()
    } catch {
        return $null
    }
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return ("{0} B" -f $Bytes)
}

function Test-AdminRights {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-ReparsePoint {
    # True for symbolic links, junctions, mount points and any other reparse
    # point. Fails CLOSED: if attributes cannot be read, treat as suspicious.
    param([string]$Path)
    try {
        $attr = [System.IO.File]::GetAttributes($Path)
        return (($attr -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint)
    } catch {
        return $true
    }
}

function Test-AnyAncestorReparse {
    # Walk every ANCESTOR directory of $Path (excluding the leaf). Returns the
    # first ancestor that is a reparse point, else $null. This catches the case
    # where a cache target sits inside a junction/symlink that points elsewhere.
    param([string]$Path)
    try {
        $p = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    } catch {
        return $null
    }
    $parent = Split-Path -Parent $p
    while ($parent -and ($parent -notmatch '^[A-Za-z]:\\?$') -and ($parent -ne $p)) {
        if (Test-Path -LiteralPath $parent) {
            if (Test-ReparsePoint $parent) { return $parent }
        }
        $p = $parent
        $parent = Split-Path -Parent $parent
    }
    return $null
}

# ============================================================================
#  LOGGING + CSV
# ============================================================================

function Initialize-Logging {
    $stamp = $Script:StartTime.ToString('yyyy-MM-dd_HH-mm-ss')
    $dir = $null
    $file = $null

    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        $isDir = $false
        if (Test-Path -LiteralPath $LogPath -PathType Container) { $isDir = $true }
        elseif ($LogPath.EndsWith('\') -or $LogPath.EndsWith('/')) { $isDir = $true }

        if ($isDir) {
            $dir  = $LogPath
            $file = Join-Path $dir ("ClearData_{0}_{1}.log" -f $stamp, $PID)
        } else {
            $file = $LogPath
            $dir  = Split-Path -Parent $file
            if ([string]::IsNullOrWhiteSpace($dir)) { $dir = (Get-Location).Path }
        }
    } else {
        $dir  = $env:TEMP
        $file = Join-Path $dir ("ClearData_{0}_{1}.log" -f $stamp, $PID)
    }

    try {
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        }
    } catch { }

    $Script:LogFile = $file
    $Script:CsvFile = [System.IO.Path]::ChangeExtension($file, '.csv')

    Write-Log 'INFO' '============================================================'
    Write-Log 'INFO' ("ClearData.Safe.ps1 v{0}" -f $Script:Version)
    Write-Log 'INFO' ("Timestamp        : {0}" -f $Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Log 'INFO' ("Mode             : {0}" -f $Mode)
    Write-Log 'INFO' ("Administrator    : {0}" -f $Script:IsAdmin)
    Write-Log 'INFO' ("MinimumAgeHours  : {0}" -f $MinimumAgeHours)
    Write-Log 'INFO' ("Cutoff (older<)  : {0}" -f $Script:Cutoff.ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Log 'INFO' ("CanResolveLinks  : {0}" -f $Script:CanResolveLinks)
    Write-Log 'INFO' ("PSVersion        : {0}" -f $PSVersionTable.PSVersion.ToString())
    Write-Log 'INFO' ("Host             : {0}" -f $env:COMPUTERNAME)
    Write-Log 'INFO' ("LogFile          : {0}" -f $Script:LogFile)
    Write-Log 'INFO' '============================================================'
}

function Write-Log {
    # Append via .NET so the byte encoding (UTF-8, no BOM) is identical on
    # Windows PowerShell 5.1 and PowerShell 7+.
    param(
        [string]$Level,
        [string]$Message
    )
    if (-not $Script:LogFile) { return }
    try {
        $line = "[{0}] [{1}] {2}`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        [System.IO.File]::AppendAllText($Script:LogFile, $line, $Script:LogEncoding)
    } catch { }
}

function Write-Both {
    # Write to console (colored) and to the log file.
    param(
        [string]$Message,
        [string]$Color = 'Gray',
        [string]$Level = 'INFO'
    )
    Write-Host $Message -ForegroundColor $Color
    Write-Log $Level ($Message.Trim())
}

# ============================================================================
#  PROTECTED PATH MODEL
#
#  ExactProtected : the path itself must never be a cleanup root, and no
#                   cleanup root may be an ANCESTOR of it. Specific deeper
#                   sub-folders ARE allowed (e.g. we clean C:\Windows\Temp even
#                   though C:\Windows is protected).
#
#  TreeProtected  : the entire subtree is off-limits. A cleanup root may never
#                   equal, be inside, or be an ancestor of any of these.
# ============================================================================

function Get-DownloadsPath {
    try {
        $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        $name = '{374DE290-123F-4565-9164-39C4925E467B}'
        $val = (Get-ItemProperty -Path $key -Name $name -ErrorAction Stop).$name
        if ($val) { return [Environment]::ExpandEnvironmentVariables($val) }
    } catch { }
    return (Join-Path $env:USERPROFILE 'Downloads')
}

function Initialize-ProtectedPaths {
    $exact = New-Object System.Collections.Generic.List[string]
    $tree  = New-Object System.Collections.Generic.List[string]

    # --- ExactProtected (block self + block being an ancestor) ---
    $userProfileFallback = Join-Path (Join-Path $env:SystemDrive 'Users') $env:USERNAME
    foreach ($p in @(
            $env:USERPROFILE,
            $userProfileFallback,
            $env:ProgramData,
            $env:SystemRoot,
            $env:windir
        )) {
        $n = Get-NormalizedPath $p
        if ($n) { [void]$exact.Add($n) }
    }

    # --- TreeProtected (whole subtree off-limits) ---
    $sys = $env:SystemRoot
    if (-not $sys) { $sys = 'C:\Windows' }

    $treeCandidates = @(
        (Join-Path $sys 'System32'),
        (Join-Path $sys 'SysWOW64'),
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        [Environment]::GetFolderPath('DesktopDirectory'),
        [Environment]::GetFolderPath('MyDocuments'),
        [Environment]::GetFolderPath('MyPictures'),
        [Environment]::GetFolderPath('MyVideos'),
        [Environment]::GetFolderPath('MyMusic'),
        (Get-DownloadsPath),
        $env:OneDrive,
        $env:OneDriveConsumer,
        $env:OneDriveCommercial,
        (Join-Path $env:USERPROFILE '.ssh'),
        (Join-Path $env:USERPROFILE '.gnupg')
    )

    # Any OneDrive*/Dropbox/Google Drive sync roots under the user profile.
    try {
        Get-ChildItem -LiteralPath $env:USERPROFILE -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(OneDrive|Dropbox|Google Drive|GoogleDrive)' } |
            ForEach-Object { $treeCandidates += $_.FullName }
    } catch { }

    foreach ($p in $treeCandidates) {
        $n = Get-NormalizedPath $p
        if ($n) { [void]$tree.Add($n) }
    }

    $Script:ExactProtected = $exact | Select-Object -Unique
    $Script:TreeProtected  = $tree  | Select-Object -Unique
}

function Test-ProtectedListsSane {
    # Defense in depth: the protected lists must contain the core anchors before
    # we are willing to delete anything. If env vars were unset/tampered, refuse.
    $needUser = Get-NormalizedPath $env:USERPROFILE
    $needWin  = Get-NormalizedPath $env:SystemRoot
    if (-not $needWin) { $needWin = Get-NormalizedPath 'C:\Windows' }
    $haveUser = ($needUser -and $Script:ExactProtected -contains $needUser)
    $haveWin  = ($needWin  -and $Script:ExactProtected -contains $needWin)
    return ($haveUser -and $haveWin)
}

function Get-DangerousReason {
    # Returns a non-empty reason string if the normalized path is dangerous.
    param([string]$Norm)
    if ([string]::IsNullOrWhiteSpace($Norm)) { return 'Empty' }

    if ($Norm -match '^[a-z]:$') { return 'DriveRoot' }

    foreach ($p in $Script:ExactProtected) {
        if ($Norm -eq $p) { return ("ExactProtected:{0}" -f $p) }
        if ($p.StartsWith($Norm + '\')) { return ("AncestorOfProtected:{0}" -f $p) }
    }

    foreach ($t in $Script:TreeProtected) {
        if ($Norm -eq $t) { return ("TreeProtected:{0}" -f $t) }
        if ($Norm.StartsWith($t + '\')) { return ("InsideProtectedTree:{0}" -f $t) }
        if ($t.StartsWith($Norm + '\')) { return ("AncestorOfProtectedTree:{0}" -f $t) }
    }

    return $null
}

function Test-SafeContainer {
    # Validate that $Path is acceptable as a cleanup ROOT (we will only ever
    # delete eligible children inside it - never the root itself).
    param([string]$Path)

    $result = [pscustomobject]@{ Safe = $false; Reason = ''; FullPath = $null; RealPath = $null }

    if ([string]::IsNullOrWhiteSpace($Path)) { $result.Reason = 'Empty'; return $result }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)

    # Reject a drive-relative reference (e.g. "C:" or "C:foo") BEFORE GetFullPath
    # can silently re-interpret it against the current directory on that drive.
    if ($expanded -match '^[A-Za-z]:($|[^\\/])') { $result.Reason = 'DriveRelative'; return $result }

    $full = $null
    try { $full = [System.IO.Path]::GetFullPath($expanded) }
    catch { $result.Reason = 'Unresolvable'; return $result }

    # Reject a drive root (e.g. "C:\") on the UNTRIMMED full path.
    if ($full -match '^[A-Za-z]:\\?$') { $result.Reason = 'DriveRoot'; $result.FullPath = $full.TrimEnd('\', '/'); return $result }

    $full = $full.TrimEnd('\', '/')
    $result.FullPath = $full

    if (-not (Test-Path -LiteralPath $full)) { $result.Reason = 'NotExist'; return $result }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { $result.Reason = 'NotADirectory'; return $result }

    $norm = Get-NormalizedPath $full
    if (-not $norm) { $result.Reason = 'Unresolvable'; return $result }

    # Require at least drive + 2 levels deep (blocks C:\, C:\Windows, C:\Users).
    $parts = $norm.Split('\') | Where-Object { $_ -ne '' }
    if ($parts.Count -lt 3) { $result.Reason = 'TooShallow'; return $result }

    $danger = Get-DangerousReason $norm
    if ($danger) { $result.Reason = $danger; return $result }

    # The container itself must not be a reparse point.
    if (Test-ReparsePoint $full) { $result.Reason = 'ReparsePoint'; return $result }

    # Ancestor junction/symlink defense: if any ancestor is a reparse point,
    # resolve the REAL on-disk target and re-check it against protected paths.
    # Fail CLOSED when resolution is unavailable.
    $ancestorLink = Test-AnyAncestorReparse $full
    if ($ancestorLink) {
        $real = Resolve-RealPath $full
        if (-not $real) {
            $result.Reason = ("AncestorReparse(unresolved):{0}" -f $ancestorLink)
            return $result
        }
        $realNorm = Get-NormalizedPath $real
        if (-not $realNorm) { $result.Reason = 'AncestorReparse(unresolvable-real)'; return $result }
        $realDanger = Get-DangerousReason $realNorm
        if ($realDanger) { $result.Reason = ("ResolvedProtected:{0}" -f $realDanger); return $result }
        $realParts = $realNorm.Split('\') | Where-Object { $_ -ne '' }
        if ($realParts.Count -lt 3) { $result.Reason = 'ResolvedTooShallow'; return $result }
        $result.RealPath = $real
    }

    $result.Safe = $true
    return $result
}

function Register-Allowlist {
    param([string]$Path)
    $n = Get-NormalizedPath $Path
    if ($n) { [void]$Script:Allowlist.Add($n) }
}

# ============================================================================
#  CONTAINER SCAN + SAFE DELETE
# ============================================================================

function Get-ContainerStats {
    # Walk a validated container WITHOUT following reparse points and collect
    # files older than the cutoff (and matching optional patterns).
    param(
        [string]$Root,
        [datetime]$Cutoff,
        [string[]]$IncludePatterns
    )

    $stats = [pscustomobject]@{
        EligibleFiles       = (New-Object System.Collections.Generic.List[string])
        EligibleBytes       = [long]0
        TotalFiles          = 0
        SkippedRecent       = 0
        SkippedReparse      = 0
        SkippedInaccessible = 0
        Dirs                = (New-Object System.Collections.Generic.List[string])
    }

    $stack = New-Object System.Collections.Stack
    $stack.Push($Root)

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()

        # One enumeration per directory; capture (don't silently swallow) errors.
        $gciErr = $null
        $entries = Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue -ErrorVariable gciErr
        if ($gciErr -and $gciErr.Count -gt 0) { $stats.SkippedInaccessible += $gciErr.Count }

        foreach ($e in $entries) {
            if ($e.PSIsContainer) {
                if (($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $stats.SkippedReparse++
                    continue   # never descend into a junction/symlink/mount point
                }
                $stats.Dirs.Add($e.FullName)
                $stack.Push($e.FullName)
            } else {
                $stats.TotalFiles++
                if (($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $stats.SkippedReparse++
                    continue
                }
                if ($IncludePatterns -and $IncludePatterns.Count -gt 0) {
                    $match = $false
                    foreach ($pat in $IncludePatterns) {
                        if ($e.Name -like $pat) { $match = $true; break }
                    }
                    if (-not $match) { continue }
                }
                if ($e.LastWriteTime -lt $Cutoff) {
                    $stats.EligibleFiles.Add($e.FullName)
                    $stats.EligibleBytes += [long]$e.Length
                } else {
                    $stats.SkippedRecent++
                }
            }
        }
    }

    return $stats
}

function Remove-OneFile {
    # The ONLY function that deletes a regular junk file. Every gate is
    # re-checked here. Returns 'Deleted' | 'Skipped' | 'Failed'.
    param(
        [string]$Path,
        [string]$Container
    )

    # Hard gate: never deletes in Preview mode.
    if ($Mode -ne 'Clean') { return 'Skipped' }

    $np = Get-NormalizedPath $Path
    $nc = Get-NormalizedPath $Container
    if (-not $np -or -not $nc) { Write-Log 'WARN' "REFUSED (unresolvable): $Path"; return 'Failed' }

    # Container must be an approved allowlisted location.
    if (-not $Script:Allowlist.Contains($nc)) {
        Write-Log 'WARN' "REFUSED (container not allowlisted): $Path"
        return 'Failed'
    }
    # File must be strictly *inside* that container.
    if (-not $np.StartsWith($nc + '\')) {
        Write-Log 'WARN' "REFUSED (outside container): $Path"
        return 'Failed'
    }
    # Never a system/protected path.
    if (Get-DangerousReason $np) {
        Write-Log 'WARN' "REFUSED (protected): $Path"
        return 'Failed'
    }
    # Never follow a reparse point.
    if (Test-ReparsePoint $Path) {
        Write-Log 'WARN' "SKIP (reparse point): $Path"
        return 'Skipped'
    }

    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        Write-Log 'INFO' "DELETED: $Path"
        return 'Deleted'
    } catch {
        # Benign TOCTOU: the file vanished between scan and clean (e.g. a live
        # browser recreated its cache). Not a failure.
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Log 'INFO' "VANISHED before delete (skipped): $Path"
            return 'Skipped'
        }
        Write-Log 'ERROR' ("FAILED: {0} :: {1}" -f $Path, $_.Exception.Message)
        return 'Failed'
    }
}

function Remove-EmptyDirs {
    # Remove now-empty subdirectories (deepest first by true path depth). Never
    # removes the root, never follows reparse points, never uses -Recurse.
    param(
        [System.Collections.Generic.List[string]]$Dirs,
        [string]$Root
    )
    if ($Mode -ne 'Clean') { return }
    if (-not $Dirs -or $Dirs.Count -eq 0) { return }

    $nr = Get-NormalizedPath $Root
    # Deepest first: a descendant always has more path segments than its ancestor.
    $sorted = $Dirs | Sort-Object -Property @{ Expression = { $n = Get-NormalizedPath $_; if ($n) { $n.Split('\').Count } else { 0 } } } -Descending
    foreach ($d in $sorted) {
        $nd = Get-NormalizedPath $d
        if (-not $nd -or $nd -eq $nr) { continue }
        if (-not $nd.StartsWith($nr + '\')) { continue }
        if (Test-ReparsePoint $d) { continue }
        try {
            $remaining = @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) {
                Remove-Item -LiteralPath $d -Force -ErrorAction Stop
                Write-Log 'INFO' "RMDIR (empty): $d"
            }
        } catch {
            Write-Log 'WARN' ("RMDIR failed: {0} :: {1}" -f $d, $_.Exception.Message)
        }
    }
}

# ============================================================================
#  RESULT / REPORTING HELPERS
# ============================================================================

function New-Result {
    param([string]$Name)
    return [pscustomobject]@{
        Category     = $Name
        Containers   = 0
        Eligible     = 0
        Bytes        = [long]0
        Deleted      = 0
        Skipped      = 0
        Failed       = 0
        Inaccessible = 0
        Status       = 'OK'
    }
}

function Write-CategoryHeader {
    param([string]$Name)
    Write-Host ''
    Write-Host ("== {0} ==" -f $Name) -ForegroundColor Cyan
    Write-Log 'INFO' ("---- CATEGORY: {0} ----" -f $Name)
}

# Apply a tri-state Remove-OneFile result to a category result object.
function Add-DeleteOutcome {
    param([object]$Res, [string]$Outcome)
    switch ($Outcome) {
        'Deleted' { $Res.Deleted++ }
        'Skipped' { $Res.Skipped++ }
        default   { $Res.Failed++ }
    }
}

# ============================================================================
#  GENERIC PATH-BASED CATEGORY
# ============================================================================

function Invoke-PathCategory {
    param(
        [string]$Name,
        [string[]]$Candidates,
        [string[]]$IncludePatterns,
        [switch]$RequireAdmin
    )

    $res = New-Result $Name
    Write-CategoryHeader $Name

    if ($RequireAdmin -and -not $Script:IsAdmin) {
        Write-Both "  [SKIP] Requires Administrator - not elevated." 'Yellow' 'WARN'
        $res.Status = 'Skipped (no admin)'
        $Script:Results.Add($res)
        return
    }

    $cutoff = $Script:Cutoff
    $anyValid = $false

    foreach ($candidate in ($Candidates | Where-Object { $_ })) {
        $check = Test-SafeContainer $candidate
        if (-not $check.Safe) {
            if ($check.Reason -ne 'NotExist') {
                Write-Both ("  [SKIP] {0} :: {1}" -f $candidate, $check.Reason) 'DarkYellow' 'WARN'
            }
            continue
        }

        $full = $check.FullPath
        $norm = Get-NormalizedPath $full
        if ($Script:Processed.Contains($norm)) { continue }  # already handled elsewhere
        [void]$Script:Processed.Add($norm)

        Register-Allowlist $full
        $anyValid = $true
        $res.Containers++

        $stats = Get-ContainerStats -Root $full -Cutoff $cutoff -IncludePatterns $IncludePatterns
        $res.Eligible     += $stats.EligibleFiles.Count
        $res.Bytes        += $stats.EligibleBytes
        $res.Skipped      += ($stats.SkippedRecent + $stats.SkippedReparse)
        $res.Inaccessible += $stats.SkippedInaccessible

        Write-Both ("  [PATH] {0}" -f $full) 'Gray' 'INFO'
        Write-Both ("         eligible: {0} file(s), {1} | kept (recent): {2} | reparse-skipped: {3} | inaccessible: {4}" -f `
                $stats.EligibleFiles.Count, (Format-Bytes $stats.EligibleBytes), $stats.SkippedRecent, $stats.SkippedReparse, $stats.SkippedInaccessible) 'Gray' 'INFO'

        if ($Mode -eq 'Clean') {
            foreach ($file in $stats.EligibleFiles) {
                Add-DeleteOutcome $res (Remove-OneFile -Path $file -Container $full)
            }
            Remove-EmptyDirs -Dirs $stats.Dirs -Root $full
        }
    }

    if ($res.Inaccessible -gt 0) {
        Write-Both ("  [WARN] {0} path(s) were inaccessible and skipped (run as Administrator for full coverage)." -f $res.Inaccessible) 'DarkYellow' 'WARN'
    }

    if (-not $anyValid) {
        Write-Both "  (no applicable locations found)" 'DarkGray' 'INFO'
        if ($res.Status -eq 'OK') { $res.Status = 'Nothing to do' }
    } elseif ($res.Failed -gt 0) {
        $res.Status = ("Completed with {0} failure(s)" -f $res.Failed)
    }

    $Script:Results.Add($res)
}

# ============================================================================
#  BROWSER / APP CACHE PATH BUILDERS  (cache only - never profile data)
# ============================================================================

function Get-ChromiumCachePaths {
    param([string]$UserDataRoot)
    $out = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $UserDataRoot -PathType Container)) { return $out }

    foreach ($s in @('ShaderCache', 'GrShaderCache', 'GraphiteDawnCache', 'component_crx_cache')) {
        $out.Add((Join-Path $UserDataRoot $s))
    }

    $profiles = Get-ChildItem -LiteralPath $UserDataRoot -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(Default|Profile \d+|Guest Profile|System Profile)$' }

    foreach ($p in $profiles) {
        foreach ($s in @(
                'Cache', 'Code Cache', 'GPUCache', 'Media Cache',
                'ShaderCache', 'GrShaderCache', 'DawnCache', 'DawnGraphiteCache',
                'Service Worker\CacheStorage', 'Service Worker\ScriptCache')) {
            $out.Add((Join-Path $p.FullName $s))
        }
    }
    return $out
}

function Get-FirefoxCachePaths {
    $out = New-Object System.Collections.Generic.List[string]
    $base = Join-Path $env:LOCALAPPDATA 'Mozilla\Firefox\Profiles'
    if (-not (Test-Path -LiteralPath $base -PathType Container)) { return $out }
    foreach ($p in (Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue)) {
        foreach ($s in @('cache2', 'startupCache', 'shader-cache', 'jumpListCache', 'OfflineCache', 'thumbnails')) {
            $out.Add((Join-Path $p.FullName $s))
        }
    }
    return $out
}

function Get-AllBrowserCachePaths {
    $list = New-Object System.Collections.Generic.List[string]
    $local = $env:LOCALAPPDATA

    $chromiumRoots = @(
        (Join-Path $local 'Google\Chrome\User Data'),
        (Join-Path $local 'Microsoft\Edge\User Data'),
        (Join-Path $local 'BraveSoftware\Brave-Browser\User Data')
    )
    foreach ($r in $chromiumRoots) {
        foreach ($x in (Get-ChromiumCachePaths $r)) { $list.Add($x) }
    }
    foreach ($x in (Get-FirefoxCachePaths)) { $list.Add($x) }
    return $list
}

function Get-AppCachePaths {
    # Electron app caches - cache subfolders only, never the app/profile root.
    $out = New-Object System.Collections.Generic.List[string]
    $appdata = $env:APPDATA
    $local   = $env:LOCALAPPDATA
    $cacheSubs = @('Cache', 'Code Cache', 'GPUCache', 'Media Cache', 'CachedData')
    $electronRoots = @(
        (Join-Path $appdata 'Microsoft\Teams'),
        (Join-Path $appdata 'Code'),
        (Join-Path $appdata 'Slack'),
        (Join-Path $appdata 'discord')
    )
    foreach ($root in $electronRoots) {
        if (Test-Path -LiteralPath $root -PathType Container) {
            foreach ($s in $cacheSubs) { $out.Add((Join-Path $root $s)) }
        }
    }
    # New Teams (Store package): clear LocalCache only, never the package root.
    $pkgRoot = Join-Path $local 'Packages'
    if (Test-Path -LiteralPath $pkgRoot -PathType Container) {
        Get-ChildItem -LiteralPath $pkgRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'MSTeams_*' } |
            ForEach-Object { $out.Add((Join-Path $_.FullName 'LocalCache')) }
    }
    return $out
}

function Stop-BrowsersIfRequested {
    # Only acts in Clean mode. Preview never changes system state.
    $names = @('chrome', 'msedge', 'brave', 'firefox')
    $running = @()
    foreach ($n in $names) {
        $p = Get-Process -Name $n -ErrorAction SilentlyContinue
        if ($p) { $running += $n }
    }

    if ($ForceCloseBrowsers -and $Mode -eq 'Clean') {
        if ($running.Count -gt 0) {
            Write-Both ("  [BROWSER] Closing (unsaved tabs/forms may be lost): {0}" -f ($running -join ', ')) 'Yellow' 'WARN'
            # Try a graceful close first so the browser can save its session.
            foreach ($n in $running) {
                try {
                    Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
                } catch { }
            }
            $deadline = (Get-Date).AddSeconds(5)
            $still = $running
            do {
                Start-Sleep -Milliseconds 500
                $still = @($running | Where-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue })
            } while ($still.Count -gt 0 -and (Get-Date) -lt $deadline)
            # Force-kill only what refused to close.
            foreach ($n in $still) {
                try { Stop-Process -Name $n -Force -ErrorAction SilentlyContinue } catch { }
            }
        }
    } elseif ($running.Count -gt 0) {
        Write-Both ("  [BROWSER] Running: {0}. Locked cache files will be skipped. Use -ForceCloseBrowsers (Clean mode) to close them." -f ($running -join ', ')) 'Yellow' 'WARN'
    }
}

# ============================================================================
#  ALL-USERS CANDIDATES
# ============================================================================

function Get-AllUsersCandidates {
    $list = New-Object System.Collections.Generic.List[string]
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    if (-not (Test-Path -LiteralPath $usersRoot -PathType Container)) { return $list }

    $exclude = @('Default', 'Default User', 'Public', 'All Users', 'desktop.ini')
    $profiles = Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $exclude -notcontains $_.Name }

    foreach ($u in $profiles) {
        $b = $u.FullName
        $list.Add((Join-Path $b 'AppData\Local\Temp'))
        $list.Add((Join-Path $b 'AppData\Local\Microsoft\Windows\INetCache'))
        $list.Add((Join-Path $b 'AppData\Local\Microsoft\Windows\WER\ReportArchive'))
        $list.Add((Join-Path $b 'AppData\Local\Microsoft\Windows\WER\ReportQueue'))
        $list.Add((Join-Path $b 'AppData\Local\D3DSCache'))
    }
    return $list
}

# ============================================================================
#  SPECIAL CATEGORIES
# ============================================================================

function Invoke-RecycleBinCleanup {
    $res = New-Result 'Recycle Bin'
    Write-CategoryHeader 'Recycle Bin'

    if ($MinimumAgeHours -gt 0) {
        Write-Both "  [NOTE] The OS empties the Recycle Bin in full; -MinimumAgeHours does not apply here." 'DarkYellow' 'WARN'
    }

    $count = 0
    $bytes = [long]0
    $shell = $null
    $enumOk = $true
    try {
        $shell = New-Object -ComObject Shell.Application
        $bin = $shell.NameSpace(0x0A)   # ssfBITBUCKET
        if ($bin) {
            foreach ($item in $bin.Items()) {
                $count++
                try { $bytes += [long]$item.Size } catch { }
            }
        } else {
            $enumOk = $false
            Write-Both "  [WARN] Recycle Bin namespace unavailable; size preview skipped." 'DarkYellow' 'WARN'
        }
    } catch {
        $enumOk = $false
        Write-Both ("  [WARN] Could not enumerate Recycle Bin: {0}" -f $_.Exception.Message) 'DarkYellow' 'WARN'
    } finally {
        if ($shell) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch { } }
    }

    $res.Eligible = $count
    $res.Bytes = $bytes
    Write-Both ("  items: {0}, approx size: {1}" -f $count, (Format-Bytes $bytes)) 'Gray' 'INFO'

    if ($Mode -eq 'Clean') {
        if ($enumOk -and $count -eq 0) {
            Write-Both "  [OK] Recycle Bin already empty." 'Green' 'INFO'
        } else {
            try {
                Clear-RecycleBin -Force -ErrorAction Stop
                $res.Deleted = $count
                Write-Both ("  [OK] Recycle Bin emptied (all drives); approx items: {0}" -f $count) 'Green' 'INFO'
            } catch {
                $res.Failed = 1
                $res.Status = 'Failed'
                Write-Both ("  [FAIL] {0}" -f $_.Exception.Message) 'Red' 'ERROR'
            }
        }
    }
    $Script:Results.Add($res)
}

function Invoke-ServiceGatedCleanup {
    # Shared engine for Windows Update / Delivery Optimization cleanup. In Clean
    # mode: stop services -> VERIFY stopped -> delete -> restart (with retries),
    # loudly reporting any service that will not stop or restart.
    param(
        [string]$Name,
        [string[]]$Candidates,
        [string[]]$ServiceNames
    )

    $res = New-Result $Name
    Write-CategoryHeader $Name

    if (-not $Script:IsAdmin) {
        Write-Both "  [SKIP] Requires Administrator - not elevated." 'Yellow' 'WARN'
        $res.Status = 'Skipped (no admin)'
        $Script:Results.Add($res)
        return
    }

    $cutoff = $Script:Cutoff
    $validContainers = New-Object System.Collections.Generic.List[object]

    foreach ($candidate in ($Candidates | Where-Object { $_ })) {
        $check = Test-SafeContainer $candidate
        if (-not $check.Safe) {
            if ($check.Reason -ne 'NotExist') {
                Write-Both ("  [SKIP] {0} :: {1}" -f $candidate, $check.Reason) 'DarkYellow' 'WARN'
            }
            continue
        }
        $full = $check.FullPath
        $norm = Get-NormalizedPath $full
        if ($Script:Processed.Contains($norm)) { continue }
        [void]$Script:Processed.Add($norm)
        Register-Allowlist $full

        $stats = Get-ContainerStats -Root $full -Cutoff $cutoff -IncludePatterns $null
        $res.Containers++
        $res.Eligible     += $stats.EligibleFiles.Count
        $res.Bytes        += $stats.EligibleBytes
        $res.Skipped      += ($stats.SkippedRecent + $stats.SkippedReparse)
        $res.Inaccessible += $stats.SkippedInaccessible

        Write-Both ("  [PATH] {0}" -f $full) 'Gray' 'INFO'
        Write-Both ("         eligible: {0} file(s), {1}" -f $stats.EligibleFiles.Count, (Format-Bytes $stats.EligibleBytes)) 'Gray' 'INFO'

        $validContainers.Add([pscustomobject]@{ Path = $full; Stats = $stats })
    }

    if ($validContainers.Count -eq 0) {
        Write-Both "  (no applicable locations found)" 'DarkGray' 'INFO'
        if ($res.Status -eq 'OK') { $res.Status = 'Nothing to do' }
        $Script:Results.Add($res)
        return
    }

    if ($Mode -eq 'Clean') {
        $wasRunning = @()
        $allStopped = $true
        try {
            foreach ($svc in $ServiceNames) {
                $o = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if (-not $o) {
                    Write-Both ("  [SVC] {0} not present on this system; related files may stay locked." -f $svc) 'DarkYellow' 'WARN'
                    continue
                }
                if ($o.Status -eq 'Running') {
                    $wasRunning += $svc
                    Write-Both ("  [SVC] stopping {0}" -f $svc) 'Gray' 'INFO'
                    try {
                        Stop-Service -Name $svc -Force -ErrorAction Stop
                        $o.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                    } catch {
                        Write-Both ("  [WARN] {0} did not stop ({1}); skipping deletion to avoid locked-file churn." -f $svc, $_.Exception.Message) 'DarkYellow' 'WARN'
                        $allStopped = $false
                    }
                }
            }

            if ($allStopped) {
                foreach ($c in $validContainers) {
                    foreach ($file in $c.Stats.EligibleFiles) {
                        Add-DeleteOutcome $res (Remove-OneFile -Path $file -Container $c.Path)
                    }
                    Remove-EmptyDirs -Dirs $c.Stats.Dirs -Root $c.Path
                }
            } else {
                $res.Status = 'Skipped (service would not stop)'
            }
        } finally {
            foreach ($svc in $wasRunning) {
                $ok = $false
                for ($i = 0; $i -lt 3 -and -not $ok; $i++) {
                    Start-Service -Name $svc -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                    if ($s -and $s.Status -eq 'Running') { $ok = $true }
                }
                if ($ok) {
                    Write-Both ("  [SVC] restarted {0}" -f $svc) 'Gray' 'INFO'
                } else {
                    Write-Both ("  [ERROR] FAILED to restart service '{0}'. Restore it manually: Start-Service {0}" -f $svc) 'Red' 'ERROR'
                }
            }
        }
        if ($res.Failed -gt 0 -and $res.Status -eq 'OK') {
            $res.Status = ("Completed with {0} failure(s)" -f $res.Failed)
        }
    }

    $Script:Results.Add($res)
}

function Invoke-DismCleanup {
    $res = New-Result 'DISM Component Cleanup'
    Write-CategoryHeader 'DISM Component Cleanup'

    if (-not $Script:IsAdmin) {
        Write-Both "  [SKIP] Requires Administrator - not elevated." 'Yellow' 'WARN'
        $res.Status = 'Skipped (no admin)'
        $Script:Results.Add($res)
        return
    }

    Write-Both "  NOTE: Uses /StartComponentCleanup only. /ResetBase is NOT used," 'Yellow' 'WARN'
    Write-Both "        so previously installed updates remain removable." 'Yellow' 'WARN'

    if ($Mode -ne 'Clean') {
        Write-Both "  [PREVIEW] Would run: DISM.exe /Online /Cleanup-Image /StartComponentCleanup" 'Gray' 'INFO'
        $res.Status = 'Preview only'
        $Script:Results.Add($res)
        return
    }

    Write-Both "  Running DISM.exe /Online /Cleanup-Image /StartComponentCleanup (may take several minutes)..." 'Cyan' 'INFO'
    try {
        $proc = Start-Process -FilePath 'dism.exe' `
            -ArgumentList '/Online', '/Cleanup-Image', '/StartComponentCleanup' `
            -Wait -PassThru -NoNewWindow -ErrorAction Stop
        Write-Both ("  DISM exit code: {0}" -f $proc.ExitCode) 'Gray' 'INFO'
        if ($proc.ExitCode -eq 0) {
            $res.Status = 'OK'
        } elseif ($proc.ExitCode -eq 3010) {
            $res.Status = 'OK (reboot required)'
            Write-Both "  NOTE: DISM completed; a reboot is required to finish." 'Yellow' 'WARN'
        } else {
            $res.Failed = 1
            $res.Status = ("DISM exit code {0}" -f $proc.ExitCode)
        }
    } catch {
        $res.Failed = 1
        $res.Status = 'Failed'
        Write-Both ("  [FAIL] {0}" -f $_.Exception.Message) 'Red' 'ERROR'
    }
    $Script:Results.Add($res)
}

function Invoke-ArchivedEventLogCleanup {
    # Dedicated, tightly-scoped routine. winevt\Logs lives under System32 (a
    # protected tree), so this does NOT use the generic engine. It only ever
    # matches the rolled-over Archive-*.evtx files and never the active logs.
    $res = New-Result 'Archived Event Logs'
    Write-CategoryHeader 'Archived Event Logs'
    Write-Both "  WARNING: Archived event logs can be valuable for security / forensic review." 'Yellow' 'WARN'

    if (-not $Script:IsAdmin) {
        Write-Both "  [SKIP] Requires Administrator - not elevated." 'Yellow' 'WARN'
        $res.Status = 'Skipped (no admin)'
        $Script:Results.Add($res)
        return
    }

    $dir = Join-Path $env:SystemRoot 'System32\winevt\Logs'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        Write-Both "  (winevt\Logs not found)" 'DarkGray' 'INFO'
        $res.Status = 'Nothing to do'
        $Script:Results.Add($res)
        return
    }
    if (Test-ReparsePoint $dir) {
        Write-Both "  [SKIP] winevt\Logs is a reparse point." 'DarkYellow' 'WARN'
        $res.Status = 'Skipped (reparse)'
        $Script:Results.Add($res)
        return
    }

    $cutoff = $Script:Cutoff
    $dirNorm = Get-NormalizedPath $dir
    $files = Get-ChildItem -LiteralPath $dir -Force -File -Filter 'Archive-*.evtx' -ErrorAction SilentlyContinue

    $eligible = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        if (($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $res.Skipped++; continue }
        if ($f.LastWriteTime -lt $cutoff) {
            $eligible.Add($f)
            $res.Eligible++
            $res.Bytes += [long]$f.Length
        } else { $res.Skipped++ }
    }
    $res.Containers = 1
    Write-Both ("  [PATH] {0}" -f $dir) 'Gray' 'INFO'
    Write-Both ("         eligible Archive-*.evtx: {0}, {1}" -f $res.Eligible, (Format-Bytes $res.Bytes)) 'Gray' 'INFO'

    if ($Mode -eq 'Clean') {
        foreach ($f in $eligible) {
            # Hard, redundant pattern + location lock.
            if ($f.Name -notlike 'Archive-*.evtx') { continue }
            if ((Get-NormalizedPath $f.DirectoryName) -ne $dirNorm) { continue }
            try {
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                Write-Log 'INFO' "DELETED (archive log): $($f.FullName)"
                $res.Deleted++
            } catch {
                Write-Log 'ERROR' ("FAILED: {0} :: {1}" -f $f.FullName, $_.Exception.Message)
                $res.Failed++
            }
        }
        if ($res.Failed -gt 0) { $res.Status = ("Completed with {0} failure(s)" -f $res.Failed) }
    }
    $Script:Results.Add($res)
}

function Invoke-MemoryDumpCleanup {
    # C:\Windows\MEMORY.DMP is a single FILE directly under the (protected)
    # Windows root. We delete the file with a hard name + parent assertion - we
    # never operate on the Windows folder itself.
    $res = New-Result 'Kernel Memory Dump'
    Write-CategoryHeader 'Kernel Memory Dump (MEMORY.DMP)'
    Write-Both "  WARNING: kernel memory dumps may be useful for debugging crashes." 'Yellow' 'WARN'

    if (-not $Script:IsAdmin) {
        Write-Both "  [SKIP] Requires Administrator - not elevated." 'Yellow' 'WARN'
        $res.Status = 'Skipped (no admin)'
        $Script:Results.Add($res)
        return
    }

    $file = Join-Path $env:SystemRoot 'MEMORY.DMP'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Write-Both "  (no MEMORY.DMP present)" 'DarkGray' 'INFO'
        $res.Status = 'Nothing to do'
        $Script:Results.Add($res)
        return
    }

    $cutoff = $Script:Cutoff
    $item = Get-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    if (-not $item) { $res.Status = 'Nothing to do'; $Script:Results.Add($res); return }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-Both "  [SKIP] reparse point." 'DarkYellow' 'WARN'
        $res.Status = 'Skipped (reparse)'
        $Script:Results.Add($res)
        return
    }
    if ($item.LastWriteTime -ge $cutoff) {
        Write-Both "  (MEMORY.DMP is newer than MinimumAgeHours - kept)" 'DarkGray' 'INFO'
        $res.Skipped = 1
        $res.Status = 'Nothing to do'
        $Script:Results.Add($res)
        return
    }

    $res.Eligible = 1
    $res.Bytes = [long]$item.Length
    Write-Both ("  eligible: {0}" -f (Format-Bytes $item.Length)) 'Gray' 'INFO'

    if ($Mode -eq 'Clean') {
        $expectedParent = Get-NormalizedPath $env:SystemRoot
        if (($item.Name -eq 'MEMORY.DMP') -and ((Get-NormalizedPath $item.DirectoryName) -eq $expectedParent)) {
            try {
                Remove-Item -LiteralPath $file -Force -ErrorAction Stop
                Write-Log 'INFO' "DELETED (memory dump): $file"
                $res.Deleted = 1
            } catch {
                $res.Failed = 1
                $res.Status = 'Failed'
                Write-Both ("  [FAIL] {0}" -f $_.Exception.Message) 'Red' 'ERROR'
            }
        }
    }
    $Script:Results.Add($res)
}

# ============================================================================
#  SUMMARY + CSV
# ============================================================================

function Write-Summary {
    $totalEligible = 0
    $totalBytes = [long]0
    $totalDeleted = 0
    $totalSkipped = 0
    $totalFailed = 0
    $totalInaccessible = 0
    foreach ($r in $Script:Results) {
        $totalEligible += $r.Eligible
        $totalBytes    += $r.Bytes
        $totalDeleted  += $r.Deleted
        $totalSkipped  += $r.Skipped
        $totalFailed   += $r.Failed
        $totalInaccessible += $r.Inaccessible
    }

    $fmt = '{0,-30} {1,8} {2,11} {3,8} {4,8} {5,7}'
    Write-Host ''
    Write-Host '======================================= SUMMARY =======================================' -ForegroundColor Cyan
    Write-Host ($fmt -f 'Category', 'Eligible', 'Size', 'Deleted', 'Skipped', 'Failed') -ForegroundColor White
    Write-Host ($fmt -f ('-' * 30), '--------', '-----------', '-------', '-------', '------') -ForegroundColor DarkGray

    foreach ($r in $Script:Results) {
        $color = 'Gray'
        if ($r.Failed -gt 0) { $color = 'Yellow' }
        if ($r.Status -like 'Skipped*') { $color = 'DarkYellow' }
        Write-Host ($fmt -f `
                ($r.Category.PadRight(30).Substring(0, 30)), $r.Eligible, (Format-Bytes $r.Bytes), $r.Deleted, $r.Skipped, $r.Failed) -ForegroundColor $color
    }

    Write-Host ($fmt -f ('-' * 30), '--------', '-----------', '-------', '-------', '------') -ForegroundColor DarkGray
    Write-Host ($fmt -f 'TOTAL', $totalEligible, (Format-Bytes $totalBytes), $totalDeleted, $totalSkipped, $totalFailed) -ForegroundColor White
    Write-Host ''
    Write-Host 'Note: sizes are nominal file sizes; hard-linked files may overstate reclaimed space.' -ForegroundColor DarkGray
    if ($totalInaccessible -gt 0) {
        Write-Host ("Note: {0} path(s) were inaccessible and skipped (try running as Administrator)." -f $totalInaccessible) -ForegroundColor DarkYellow
    }

    Write-Log 'INFO' '---- SUMMARY ----'
    foreach ($r in $Script:Results) {
        Write-Log 'INFO' ("{0} | eligible={1} | size={2} | deleted={3} | skipped={4} | failed={5} | inaccessible={6} | status={7}" -f `
                $r.Category, $r.Eligible, (Format-Bytes $r.Bytes), $r.Deleted, $r.Skipped, $r.Failed, $r.Inaccessible, $r.Status)
    }
    Write-Log 'INFO' ("TOTAL | eligible={0} | size={1} | deleted={2} | skipped={3} | failed={4} | inaccessible={5}" -f `
            $totalEligible, (Format-Bytes $totalBytes), $totalDeleted, $totalSkipped, $totalFailed, $totalInaccessible)

    $elapsed = (Get-Date) - $Script:StartTime
    Write-Log 'INFO' ("Elapsed: {0:N1}s" -f $elapsed.TotalSeconds)

    if ($Mode -eq 'Preview') {
        Write-Host ("PREVIEW MODE - nothing was deleted. Re-run with '-Mode Clean' to apply. Reclaimable: {0}" -f (Format-Bytes $totalBytes)) -ForegroundColor Green
    } else {
        Write-Host ("CLEAN MODE complete. Deleted {0} item(s), recovered ~{1}. Failures: {2}" -f $totalDeleted, (Format-Bytes $totalBytes), $totalFailed) -ForegroundColor Green
    }

    # ----- CSV report (UTF-8 with BOM for Excel; identical bytes on 5.1 + 7) -----
    try {
        $stampStr = $Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
        $rows = foreach ($r in $Script:Results) {
            [pscustomobject]@{
                Timestamp         = $stampStr
                Mode              = $Mode
                Administrator     = $Script:IsAdmin
                MinimumAgeHours   = $MinimumAgeHours
                Category          = $r.Category
                ContainersScanned = $r.Containers
                EligibleItems     = $r.Eligible
                EstimatedBytes    = $r.Bytes
                EstimatedSize     = (Format-Bytes $r.Bytes)
                Deleted           = $r.Deleted
                Skipped           = $r.Skipped
                Failed            = $r.Failed
                Inaccessible      = $r.Inaccessible
                Status            = $r.Status
            }
        }
        $csvText = ($rows | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
        [System.IO.File]::WriteAllText($Script:CsvFile, $csvText, [System.Text.UTF8Encoding]::new($true))
        Write-Host ("CSV report : {0}" -f $Script:CsvFile) -ForegroundColor DarkGray
    } catch {
        Write-Both ("CSV report : FAILED to write '{0}': {1}" -f $Script:CsvFile, $_.Exception.Message) 'Red' 'WARN'
    }

    Write-Host ("Log file   : {0}" -f $Script:LogFile) -ForegroundColor DarkGray
}

# ============================================================================
#  MAIN
# ============================================================================

function Invoke-Main {
    $Script:IsAdmin = Test-AdminRights
    Initialize-Native
    Initialize-ProtectedPaths

    # Single, run-wide cutoff. MinimumAgeHours=0 => everything is eligible.
    if ($MinimumAgeHours -le 0) {
        $Script:Cutoff = $Script:StartTime.AddYears(100)
    } else {
        $Script:Cutoff = $Script:StartTime.AddHours(-1 * $MinimumAgeHours)
    }

    Initialize-Logging

    # Defense in depth: refuse to run if the protected-path model is degraded.
    if (-not (Test-ProtectedListsSane)) {
        Write-Host 'FATAL: protected-path model is incomplete (USERPROFILE/SystemRoot unresolved). Aborting for safety.' -ForegroundColor Red
        Write-Log 'ERROR' 'Protected-path model incomplete; aborting before any deletion.'
        return
    }

    $local = $env:LOCALAPPDATA

    # ---- Banner ----
    Write-Host ''
    Write-Host '############################################################' -ForegroundColor Cyan
    Write-Host ("#  ClearData.Safe.ps1  v{0}" -f $Script:Version) -ForegroundColor Cyan
    Write-Host ("#  Mode            : {0}" -f $Mode) -ForegroundColor $(if ($Mode -eq 'Clean') { 'Yellow' } else { 'Green' })
    Write-Host ("#  Administrator   : {0}" -f $Script:IsAdmin) -ForegroundColor Cyan
    Write-Host ("#  MinimumAgeHours : {0}" -f $MinimumAgeHours) -ForegroundColor Cyan
    Write-Host '############################################################' -ForegroundColor Cyan
    if ($Mode -eq 'Preview') {
        Write-Host 'PREVIEW (dry-run): scanning only. Nothing will be deleted.' -ForegroundColor Green
    } else {
        Write-Host 'CLEAN mode: eligible junk WILL be deleted.' -ForegroundColor Yellow
    }
    if (-not $Script:IsAdmin) {
        Write-Host 'Not elevated: admin-only categories will be skipped with a warning.' -ForegroundColor DarkYellow
    }
    if (-not $Script:CanResolveLinks) {
        Write-Host 'Note: link resolution unavailable; targets reached through a junction will be refused (fail-safe).' -ForegroundColor DarkYellow
    }

    # ---- Selection-specific warnings ----
    if ($IncludeCrashDumps)        { Write-Both '[!] Crash dumps may be useful for debugging.' 'Yellow' 'WARN' }
    if ($IncludeArchivedEventLogs) { Write-Both '[!] Archived Event Logs may be useful for security investigation / forensic review.' 'Yellow' 'WARN' }
    if ($IncludeDeveloperCaches)   { Write-Both '[!] Developer caches may need to be downloaded again later.' 'Yellow' 'WARN' }
    if ($IncludeMavenRepository)   { Write-Both '[!] ~/.m2/repository may contain locally-installed (mvn install) and SNAPSHOT artifacts that CANNOT be re-downloaded. Deleting it can break offline builds.' 'Yellow' 'WARN' }
    if ($IncludeBrowserCache)      { Write-Both '[!] Browser cache cleanup works best when browsers are closed.' 'Yellow' 'WARN' }

    # =========================================================
    #  CORE SAFE CLEANUP (always runs)
    # =========================================================
    Invoke-PathCategory 'Current User TEMP' @($env:TEMP)
    Invoke-PathCategory 'Current User TMP'  @($env:TMP)
    Invoke-PathCategory 'Windows TEMP'      @((Join-Path $env:SystemRoot 'Temp'))
    Invoke-PathCategory 'INetCache'         @((Join-Path $local 'Microsoft\Windows\INetCache'))
    Invoke-PathCategory 'Windows Caches'    @((Join-Path $local 'Microsoft\Windows\Caches'))

    $werArchive = @((Join-Path $local 'Microsoft\Windows\WER\ReportArchive'))
    $werQueue   = @((Join-Path $local 'Microsoft\Windows\WER\ReportQueue'))
    if ($Script:IsAdmin) {
        $werArchive += (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive')
        $werQueue   += (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue')
    }
    Invoke-PathCategory 'WER ReportArchive' $werArchive
    Invoke-PathCategory 'WER ReportQueue'   $werQueue
    if ($Script:IsAdmin) {
        Invoke-PathCategory 'WER Temp' @((Join-Path $env:ProgramData 'Microsoft\Windows\WER\Temp'))
    }
    Invoke-PathCategory 'DirectX Shader Cache' @((Join-Path $local 'D3DSCache'))

    # =========================================================
    #  OPTIONAL BROWSER CACHE
    # =========================================================
    if ($IncludeBrowserCache) {
        Write-Both '[*] Browser cache pre-flight: checking for running browsers...' 'Cyan' 'INFO'
        Stop-BrowsersIfRequested
        Invoke-PathCategory 'Browser Cache' (Get-AllBrowserCachePaths)
    }

    # =========================================================
    #  OPTIONAL APP (ELECTRON) CACHE
    # =========================================================
    if ($IncludeAppCaches) {
        Invoke-PathCategory 'App Caches (Electron)' (Get-AppCachePaths)
    }

    # =========================================================
    #  OPTIONAL ALL-USERS TEMP & CACHES
    # =========================================================
    if ($IncludeAllUsersTemp) {
        Write-Both "[*] All-users cleanup: other users' transient files older than MinimumAgeHours will be removed; locked/recent files are skipped." 'Yellow' 'WARN'
        Invoke-PathCategory 'All-Users Temp & Caches' (Get-AllUsersCandidates) -RequireAdmin
    }

    # =========================================================
    #  OPTIONAL WINDOWS CLEANUP
    # =========================================================
    if ($IncludeWindowsUpdateCache) {
        Invoke-ServiceGatedCleanup -Name 'Windows Update Cache' `
            -Candidates @((Join-Path $env:SystemRoot 'SoftwareDistribution\Download')) `
            -ServiceNames @('wuauserv', 'bits')
    }

    if ($IncludeDeliveryOptimizationCache) {
        Invoke-ServiceGatedCleanup -Name 'Delivery Optimization Cache' `
            -Candidates @(
                (Join-Path $local 'Microsoft\Windows\DeliveryOptimization'),
                (Join-Path $env:SystemRoot 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization')
            ) `
            -ServiceNames @('dosvc')
    }

    if ($IncludeRecycleBin) {
        Invoke-RecycleBinCleanup
    }

    if ($RunDismComponentCleanup) {
        Invoke-DismCleanup
    }

    # =========================================================
    #  OPTIONAL ADVANCED CLEANUP
    # =========================================================
    if ($IncludeThumbnailAndIconCache) {
        Invoke-PathCategory 'Thumbnail & Icon Cache' `
            @((Join-Path $local 'Microsoft\Windows\Explorer')) `
            -IncludePatterns @('thumbcache_*.db', 'iconcache_*.db')
    }

    if ($IncludePrefetch) {
        Invoke-PathCategory 'Windows Prefetch' `
            @((Join-Path $env:SystemRoot 'Prefetch')) `
            -IncludePatterns @('*.pf') `
            -RequireAdmin
    }

    if ($IncludeCrashDumps) {
        $dumpPaths = @((Join-Path $local 'CrashDumps'))
        if ($Script:IsAdmin) { $dumpPaths += (Join-Path $env:SystemRoot 'Minidump') }
        Invoke-PathCategory 'Crash Dumps' $dumpPaths -IncludePatterns @('*.dmp', '*.mdmp', '*.hdmp')
        Invoke-MemoryDumpCleanup
    }

    if ($IncludeArchivedEventLogs) {
        Invoke-ArchivedEventLogCleanup
    }

    if ($IncludeDeveloperCaches) {
        # Download caches ONLY. Never source, node_modules, venvs, .git, locks
        # or build output.
        $userProfile = $env:USERPROFILE
        $devProcs = @('java', 'gradle', 'node', 'mvn', 'Code', 'idea64', 'studio64', 'pycharm64')
        $runningDev = @($devProcs | Where-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue })
        if ($runningDev.Count -gt 0) {
            Write-Both ("  [DEV] Running: {0}. Cleaning developer caches during an active build/IDE session may break it; in-use files are skipped." -f ($runningDev -join ', ')) 'Yellow' 'WARN'
        }
        $devPaths = @(
            (Join-Path $local 'npm-cache'),
            (Join-Path $userProfile '.npm\_cacache'),
            (Join-Path $local 'pip\Cache'),
            (Join-Path $userProfile '.cache\pip'),
            (Join-Path $userProfile '.gradle\caches')
        )
        Invoke-PathCategory 'Developer Caches' $devPaths
    }

    if ($IncludeMavenRepository) {
        Invoke-PathCategory 'Maven Local Repository' @((Join-Path $env:USERPROFILE '.m2\repository'))
    }

    # =========================================================
    #  SUMMARY
    # =========================================================
    Write-Summary
}

# Auto-run only when executed directly (-File / &). When dot-sourced
# (". .\ClearData.Safe.ps1") the functions load without running Invoke-Main,
# which lets the safety gates be unit-tested in isolation.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Main
}
