$Launcher = Get-Item -LiteralPath $PSCommandPath -Force
if ($Launcher.LinkType -eq "SymbolicLink") {
    $Launcher = $Launcher.ResolveLinkTarget($true)
    if ($null -eq $Launcher) {
        Write-Error "granted-auto-auth: launcher symbolic link target is missing"
        exit 1
    }
}
$Controller = Join-Path $Launcher.DirectoryName "granted-auto-auth"
$UvCommand = @(Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue)[0]
if (-not $UvCommand) {
    Write-Error "granted-auto-auth: uv.exe is missing; install uv, then run: granted-auto-auth install"
    exit 1
}

$Uv = [System.IO.Path]::GetFullPath($UvCommand.Source)
if (-not (Test-Path -LiteralPath $Controller -PathType Leaf)) {
    Write-Error "granted-auto-auth: controller is missing"
    exit 1
}

if ($args.Count -ne 1 -or $args[0] -notin @("doctor", "enabled", "install", "uninstall")) {
    [Console]::Error.WriteLine("usage: granted-auto-auth doctor|enabled|install|uninstall")
    exit 2
}

$PreviousUvPresent = Test-Path Env:GRANTED_AUTO_AUTH_UV
$PreviousUv = $env:GRANTED_AUTO_AUTH_UV
try {
    $env:GRANTED_AUTO_AUTH_UV = $Uv
    if ($args[0] -eq "install") {
        & $Uv run --no-project --python 3.12 python $Controller @args
    }
    else {
        & $Uv run --offline --no-project --python 3.12 python $Controller @args
    }
    exit $LASTEXITCODE
}
finally {
    if ($PreviousUvPresent) {
        $env:GRANTED_AUTO_AUTH_UV = $PreviousUv
    }
    else {
        Remove-Item Env:GRANTED_AUTO_AUTH_UV -ErrorAction SilentlyContinue
    }
}
