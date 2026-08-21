<#
.SYNOPSIS
    Builds Ballast and starts it, from one command.

.DESCRIPTION
    "dotnet run --project Ballast.App" does NOT work for this app. Ballast's manifest requests
    requireAdministrator, and dotnet run launches the process without UseShellExecute, so Windows
    cannot show a UAC prompt and fails outright with:

        The requested operation requires elevation.

    This script builds normally and then starts the app with -Verb RunAs, which is what actually
    raises the UAC prompt. Accept it and the app opens.

    Keep this file ASCII-only: PowerShell 5.1 reads .ps1 as ANSI unless there is a BOM, and a
    stray non-ASCII character silently breaks the surrounding string.

.EXAMPLE
    .\run.ps1

.EXAMPLE
    .\run.ps1 -Configuration Release      # what you would actually ship
    .\run.ps1 -NoBuild                    # just start what is already built
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',

    [switch] $NoBuild
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# ---- prerequisite: the .NET 10 SDK -------------------------------------------------------
$sdks = & dotnet --list-sdks 2>$null
if (-not $sdks) {
    Write-Output "The .NET SDK was not found on PATH."
    Write-Output "Install the .NET 10 SDK: https://dotnet.microsoft.com/download/dotnet/10.0"
    exit 1
}
if (-not ($sdks | Where-Object { $_ -match '^10\.' })) {
    Write-Output "No .NET 10 SDK found. Installed SDKs:"
    $sdks | ForEach-Object { Write-Output ("  " + $_) }
    Write-Output ""
    Write-Output "Install the .NET 10 SDK (side-by-side is fine, it will not disturb anything):"
    Write-Output "  https://dotnet.microsoft.com/download/dotnet/10.0"
    exit 1
}

# ---- build -------------------------------------------------------------------------------
if (-not $NoBuild) {
    Write-Output "Building ($Configuration)..."
    & dotnet build (Join-Path $root 'Ballast.slnx') -c $Configuration -v minimal --nologo
    if ($LASTEXITCODE -ne 0) {
        Write-Output ""
        Write-Output "Build failed. If the error mentions WMC1006 and intermediatexaml, you are on"
        Write-Output "a commit older than the cold-build fix - run 'git pull' and try again."
        exit 1
    }
}

# ---- find what we just built --------------------------------------------------------------
$exe = Get-ChildItem -Path (Join-Path $root 'Ballast.App\bin') -Filter 'Ballast.App.exe' -Recurse -EA SilentlyContinue |
       Where-Object { $_.FullName -match [regex]::Escape("\$Configuration\") } |
       Sort-Object LastWriteTime -Descending |
       Select-Object -First 1

if (-not $exe) {
    Write-Output "Built, but Ballast.App.exe was not found under Ballast.App\bin. Nothing to start."
    exit 1
}

# ---- start it ------------------------------------------------------------------------------
# Already elevated? Then a plain start works and shows no second prompt.
$elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Output ""
Write-Output ("Starting " + $exe.FullName)
if (-not $elevated) { Write-Output "Windows will ask for administrator approval - accept it." }

try {
    if ($elevated) {
        Start-Process -FilePath $exe.FullName -WorkingDirectory $exe.DirectoryName
    } else {
        Start-Process -FilePath $exe.FullName -WorkingDirectory $exe.DirectoryName -Verb RunAs
    }
} catch {
    Write-Output ""
    Write-Output "Could not start it: $($_.Exception.Message)"
    Write-Output "If you declined the UAC prompt, run it again and accept."
    exit 1
}

Start-Sleep -Seconds 2
if (Get-Process -Name 'Ballast.App' -EA SilentlyContinue) {
    Write-Output "Running."
} else {
    Write-Output "It did not stay running. Check %LOCALAPPDATA%\Ballast\logs for the reason."
}
