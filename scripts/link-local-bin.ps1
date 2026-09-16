[CmdletBinding()]
param(
    [switch]$Elevated
)

$ErrorActionPreference = "Stop"

$sourceFile = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "granted-auto-auth.ps1"))
$targetDir = Join-Path $HOME ".local\bin"
$targetFile = Join-Path $targetDir "granted-auto-auth.ps1"

if (-not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
    Write-Error "granted-auto-auth: source does not exist: $sourceFile"
    exit 1
}

New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
$existing = Get-Item -LiteralPath $targetFile -Force -ErrorAction SilentlyContinue

if ($null -ne $existing) {
    if ($existing.LinkType -eq "SymbolicLink") {
        $linkTarget = @($existing.Target)[0]
        if (-not [System.IO.Path]::IsPathRooted($linkTarget)) {
            $linkTarget = Join-Path $existing.DirectoryName $linkTarget
        }
        $resolvedTarget = [System.IO.Path]::GetFullPath($linkTarget)
        if ([string]::Equals($resolvedTarget, $sourceFile, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Output "granted-auto-auth already linked: $targetFile"
            exit 0
        }
        Write-Error "granted-auto-auth: refusing to replace symbolic link: $targetFile"
        exit 1
    }
    Write-Error "granted-auto-auth: refusing to replace existing path: $targetFile"
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $Elevated) {
    $escapedScriptPath = $PSCommandPath.Replace("'", "''")
    $script = "& '$escapedScriptPath' -Elevated"
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
    try {
        $process = Start-Process pwsh -ArgumentList "-NoProfile", "-EncodedCommand", $encoded -Verb RunAs -Wait -PassThru
    } catch {
        Write-Error "granted-auto-auth: symbolic-link elevation was cancelled or failed: $targetFile"
        exit 1
    }
    exit $process.ExitCode
}

try {
    New-Item -ItemType SymbolicLink -Path $targetFile -Target $sourceFile | Out-Null
} catch {
    Write-Error "granted-auto-auth: failed to create symbolic link; enable Windows Developer Mode or run an elevated shell: $targetFile"
    exit 1
}

Write-Host "Created: $targetFile -> $sourceFile" -ForegroundColor Green
