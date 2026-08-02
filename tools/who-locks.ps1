<#
.SYNOPSIS
    Names the process (or processes) holding a file open.

.DESCRIPTION
    Uses the Restart Manager API - the same one Windows itself uses to produce
    "The action can't be completed because the file is open in <program>".
    That makes it authoritative: whatever it names really is holding the file.

    Resource Monitor can do this too, but the Associated Handles box is easy to
    confuse with the CPU-tab filter, and it will not tell you about a handle that
    was only held for a moment. This is one command and it answers directly.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\who-locks.ps1 "C:\Users\me\Desktop\report.docx"

.EXAMPLE
    # Watch a file for 60 seconds and log every process that grabs it. Use this when
    # the lock is intermittent - a sync client holds a file only while uploading it,
    # so a single check will usually miss it.
    powershell -ExecutionPolicy Bypass -File tools\who-locks.ps1 "C:\path\file" -WatchSeconds 60
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Path,

    [int] $WatchSeconds = 0
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Output "No such file: $Path"
    exit 1
}
$Path = (Resolve-Path -LiteralPath $Path).Path

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class RestartManager
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME { public uint dwLowDateTime; public uint dwHighDateTime; }

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS { public int dwProcessId; public FILETIME ProcessStartTime; }

    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded,
        ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

    /// <summary>Returns "pid|name|description" for every process holding the file.</summary>
    public static List<string> WhoIsHolding(string path)
    {
        var holders = new List<string>();

        uint session;
        string key = Guid.NewGuid().ToString();
        if (RmStartSession(out session, 0, key) != 0) return holders;

        try
        {
            if (RmRegisterResources(session, 1, new[] { path }, 0, null, 0, null) != 0) return holders;

            uint needed = 0, count = 0, reasons = 0;

            // First call asks how many entries there are.
            int result = RmGetList(session, out needed, ref count, null, ref reasons);

            if (result == 234 /* ERROR_MORE_DATA */ && needed > 0)
            {
                var infos = new RM_PROCESS_INFO[needed];
                count = needed;

                if (RmGetList(session, out needed, ref count, infos, ref reasons) == 0)
                {
                    for (int i = 0; i < count; i++)
                    {
                        string name = "(exited)";
                        try
                        {
                            var p = System.Diagnostics.Process.GetProcessById(infos[i].Process.dwProcessId);
                            name = p.ProcessName;
                        }
                        catch { }

                        holders.Add(infos[i].Process.dwProcessId + "|" + name + "|" + infos[i].strAppName);
                    }
                }
            }
        }
        finally
        {
            RmEndSession(session);
        }

        return holders;
    }
}
'@ -Language CSharp

function Show-Holders([string] $file, [string] $stamp) {
    $holders = [RestartManager]::WhoIsHolding($file)

    if ($holders.Count -eq 0) {
        if ($stamp) { return }          # in watch mode, stay quiet until something appears
        Write-Output "Nothing is holding this file right now."
        Write-Output ""
        Write-Output "If Explorer still refuses to rename it, the lock is intermittent - something"
        Write-Output "grabs the file briefly and lets go. Re-run with -WatchSeconds 60 and try the"
        Write-Output "rename while it watches."
        return
    }

    foreach ($h in $holders) {
        $parts = $h -split '\|'
        $line = "  PID $($parts[0])  $($parts[1])"
        if ($parts[2] -and $parts[2] -ne $parts[1]) { $line += "   ($($parts[2]))" }
        if ($stamp) { $line = "[$stamp]$line" }
        Write-Output $line
    }
}

Write-Output "file: $Path"
Write-Output ""

if ($WatchSeconds -le 0) {
    Show-Holders $Path $null
    exit 0
}

Write-Output "Watching for $WatchSeconds seconds. Try the rename now - every process that touches"
Write-Output "the file will be named below as it happens."
Write-Output ""

$deadline = (Get-Date).AddSeconds($WatchSeconds)
$seen = @{}

while ((Get-Date) -lt $deadline) {
    foreach ($h in [RestartManager]::WhoIsHolding($Path)) {
        if (-not $seen.ContainsKey($h)) {
            $seen[$h] = $true
            Show-Holders $Path (Get-Date -Format 'HH:mm:ss')
        }
    }
    Start-Sleep -Milliseconds 200
}

Write-Output ""
Write-Output $(if ($seen.Count -eq 0) {
    "Nothing ever held it during that window. The block is not a file lock - it may be the folder, or Explorer itself."
} else {
    "$($seen.Count) distinct holder(s) seen. Whatever is listed above is what stops the rename."
})
