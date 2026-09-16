function assume {
    $Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $Controller = Join-Path $Root "scripts\granted-auto-auth.ps1"
    $Supervisor = Join-Path $Root "scripts\granted_auto_auth_supervisor.py"
    $UvCommand = @(Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue)[0]
    if (-not $UvCommand) {
        [Console]::Error.WriteLine("assume: uv.exe is missing; run: granted-auto-auth install")
        $env:ASSUME_STATUS = "1"
        $global:LASTEXITCODE = 1
        return
    }
    $Uv = [System.IO.Path]::GetFullPath($UvCommand.Source)

    $HasReal = Test-Path Env:GRANTED_AUTO_AUTH_REAL_ASSUMEGO
    $HasDeadline = Test-Path Env:GRANTED_AUTO_AUTH_DEADLINE_NS
    if ($HasReal -xor $HasDeadline) {
        [Console]::Error.WriteLine("assume: nested automation context is incomplete")
        $env:ASSUME_STATUS = "1"
        $global:LASTEXITCODE = 1
        return
    }
    if ($HasReal) {
        $RealAssumego = $env:GRANTED_AUTO_AUTH_REAL_ASSUMEGO
        $Deadline = $env:GRANTED_AUTO_AUTH_DEADLINE_NS
    }
    else {
        $Resolved = @(Get-Command assumego.exe -CommandType Application -ErrorAction SilentlyContinue)[0]
        if (-not $Resolved) {
            [Console]::Error.WriteLine("assume: assumego.exe is missing")
            $env:ASSUME_STATUS = "127"
            $global:LASTEXITCODE = 127
            return
        }
        $RealAssumego = [System.IO.Path]::GetFullPath($Resolved.Source)
        $Deadline = (& $Uv run --offline --no-project --python 3.12 python -c "import time; print(time.monotonic_ns() + 180_000_000_000)")
        if ($LASTEXITCODE -ne 0 -or $Deadline -notmatch '^[0-9]+$') {
            [Console]::Error.WriteLine("assume: installed Python 3.12 runtime is missing; run: granted-auto-auth install")
            $env:ASSUME_STATUS = "1"
            $global:LASTEXITCODE = 1
            return
        }
    }
    $RealName = [System.IO.Path]::GetFileName($RealAssumego)
    $RealIsAbsolute = [System.IO.Path]::IsPathFullyQualified($RealAssumego)
    $RealExists = [System.IO.File]::Exists($RealAssumego)
    $RealNameMatches = $RealName -ieq "assumego.exe"
    if (-not $RealIsAbsolute -or -not $RealExists -or -not $RealNameMatches) {
        [Console]::Error.WriteLine("assume: resolved assumego.exe is invalid")
        $env:ASSUME_STATUS = "1"
        $global:LASTEXITCODE = 1
        return
    }

    $GrantedArguments = @($args)
    $ExecArguments = $null
    $ExecIndex = -1
    for ($Index = 0; $Index -lt $GrantedArguments.Count; $Index++) {
        if ($GrantedArguments[$Index] -eq "--exec") {
            $ExecIndex = $Index
            break
        }
    }
    if ($ExecIndex -ge 0) {
        if ($ExecIndex -eq 0) {
            [Console]::Error.WriteLine("assume: --exec requires Granted arguments before it")
            $env:ASSUME_STATUS = "1"
            $global:LASTEXITCODE = 1
            return
        }
        $GrantedArguments = @($args[0..($ExecIndex - 1)])
        $ChildIndex = $ExecIndex + 1
        if ($ChildIndex -lt $args.Count -and $args[$ChildIndex] -eq "--") {
            $ChildIndex++
        }
        if ($ChildIndex -ge $args.Count) {
            [Console]::Error.WriteLine("assume: --exec requires a command")
            $env:ASSUME_STATUS = "1"
            $global:LASTEXITCODE = 1
            return
        }
        $ExecArguments = @($args[$ChildIndex..($args.Count - 1)])
    }

    $MaskedNames = @("SSH_CLIENT", "SSH_TTY", "SSH_CONNECTION", "CI", "CODESPACES", "CLOUD_SHELL")
    $HelperNames = @("PATH", "SHELL", "GRANTED_ALIAS_CONFIGURED", "GRANTED_AUTO_AUTH_REAL_ASSUMEGO", "GRANTED_AUTO_AUTH_DEADLINE_NS", "CF_KEYRING_FILE_PASSWORD") + $MaskedNames
    $CredentialNames = @(
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
        "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_SESSION_EXPIRATION", "AWS_CREDENTIAL_EXPIRATION",
        "GRANTED_SSO", "GRANTED_SSO_START_URL", "GRANTED_SSO_ROLE_NAME", "GRANTED_SSO_REGION",
        "GRANTED_SSO_ACCOUNT_ID", "ASSUME_COMMAND"
    )
    $Snapshot = @{}
    foreach ($Name in ($HelperNames + $CredentialNames | Select-Object -Unique)) {
        $Snapshot[$Name] = @{
            Present = Test-Path "Env:$Name"
            Value = [System.Environment]::GetEnvironmentVariable($Name, "Process")
        }
    }
    $Restore = {
        param([string[]]$Names)
        foreach ($Name in $Names) {
            if ($Snapshot[$Name].Present) {
                [System.Environment]::SetEnvironmentVariable($Name, $Snapshot[$Name].Value, "Process")
            }
            else {
                Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
            }
        }
    }

    $Status = 1
    $CommitCredentialState = $false
    try {
        $env:SHELL = "ps"
        $env:GRANTED_ALIAS_CONFIGURED = "true"
        $env:GRANTED_AUTO_AUTH_REAL_ASSUMEGO = $RealAssumego
        $env:GRANTED_AUTO_AUTH_DEADLINE_NS = "$Deadline"
        foreach ($Name in $MaskedNames) {
            [System.Environment]::SetEnvironmentVariable($Name, "", "Process")
        }

        if (Test-Path Env:GRANTED_AUTO_AUTH_DRY_PROBE) {
            & $Controller enabled *> $null
            if ($env:GRANTED_AUTO_AUTH_DRY_PROBE -ne "1" -or $LASTEXITCODE -ne 0) {
                $Status = 1
            }
            else {
                $Status = 73
            }
            return
        }

        & $Controller enabled *> $null
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("assume: automation is not ready; run: granted-auto-auth install")
            $Status = 1
            return
        }

        $Output = @(& $Uv run --script --locked --offline $Supervisor $RealAssumego @GrantedArguments)
        $Status = $LASTEXITCODE
        if ($Status -ne 0) {
            return
        }
        $ProtocolLines = @($Output | ForEach-Object { [string]$_ } | Where-Object {
            $_ -match '^Granted(?:Assume|Desume|Output)(?:\s|$)'
        })
        if ($ProtocolLines.Count -eq 0) {
            if ($null -ne $ExecArguments) {
                [Console]::Error.WriteLine("assume: Granted protocol output is missing")
                $Status = 1
                return
            }
            return
        }
        if ($ProtocolLines.Count -ne 1) {
            [Console]::Error.WriteLine("assume: unknown or duplicate Granted protocol output")
            $Status = 1
            return
        }
        $Text = $ProtocolLines[0].Trim()
        $Fields = @($Text -split '\s+')
        $Flag = $Fields[0]
        if ($Flag -eq "GrantedAssume") {
            if ($Fields.Count -ne 13) {
                [Console]::Error.WriteLine("assume: GrantedAssume protocol is malformed: fields=$($Fields.Count)")
                $Status = 1
                return
            }
            $Values = $Fields[1..12]
            if ($Values[11] -ne "None") {
                [Console]::Error.WriteLine("assume: GrantedAssume command field is invalid")
                $Status = 1
                return
            }
            foreach ($Name in $CredentialNames[0..12]) {
                [System.Environment]::SetEnvironmentVariable($Name, "", "Process")
            }
            $ProtocolNames = @(
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
                "AWS_REGION", "AWS_SESSION_EXPIRATION", "GRANTED_SSO", "GRANTED_SSO_START_URL",
                "GRANTED_SSO_ROLE_NAME", "GRANTED_SSO_REGION", "GRANTED_SSO_ACCOUNT_ID"
            )
            for ($Index = 0; $Index -lt 11; $Index++) {
                if ($Values[$Index] -ne "None") {
                    [System.Environment]::SetEnvironmentVariable($ProtocolNames[$Index], $Values[$Index], "Process")
                }
            }
            $env:AWS_DEFAULT_REGION = $env:AWS_REGION
            $env:AWS_CREDENTIAL_EXPIRATION = $env:AWS_SESSION_EXPIRATION
            $env:ASSUME_COMMAND = [string]::Join(" ", $args)
            if ($null -ne $ExecArguments) {
                $Executable = [string]$ExecArguments[0]
                $ChildArguments = if ($ExecArguments.Count -gt 1) { @($ExecArguments[1..($ExecArguments.Count - 1)]) } else { @() }
                $global:LASTEXITCODE = 0
                & $Executable @ChildArguments
                $Status = $LASTEXITCODE
            }
            else {
                $CommitCredentialState = $true
            }
        }
        elseif ($Flag -eq "GrantedDesume") {
            if ($null -ne $ExecArguments) {
                [Console]::Error.WriteLine("assume: --exec requires GrantedAssume output")
                $Status = 1
                return
            }
            if ($Fields.Count -ne 1) {
                [Console]::Error.WriteLine("assume: GrantedDesume protocol is malformed")
                $Status = 1
                return
            }
            foreach ($Name in $CredentialNames[0..12]) {
                [System.Environment]::SetEnvironmentVariable($Name, "", "Process")
            }
            $CommitCredentialState = $true
        }
        elseif ($Flag -eq "GrantedOutput") {
            if ($null -ne $ExecArguments) {
                [Console]::Error.WriteLine("assume: --exec requires GrantedAssume output")
                $Status = 1
                return
            }
            if ($Fields.Count -lt 2) {
                [Console]::Error.WriteLine("assume: GrantedOutput protocol is malformed")
                $Status = 1
                return
            }
            Write-Host ([string]::Join(" ", $Fields[1..($Fields.Count - 1)]))
        }
        else {
            [Console]::Error.WriteLine("assume: unknown or duplicate Granted protocol output")
            $Status = 1
        }
    }
    catch [System.Management.Automation.PipelineStoppedException] {
        $Status = 130
    }
    catch {
        [Console]::Error.WriteLine("assume: adapter failure")
        $Status = 1
    }
    finally {
        & $Restore $HelperNames
        if (-not $CommitCredentialState) {
            & $Restore $CredentialNames
        }
        $env:ASSUME_STATUS = "$Status"
        $global:LASTEXITCODE = $Status
    }
}


function granted-auto-auth-doctor {
    if ($PSVersionTable.PSVersion.Major -lt 7 -or -not $IsWindows -or -not [Environment]::Is64BitOperatingSystem) {
        Write-Host "FAIL: PowerShell 7 on Windows x64 is required"
        return
    }
    $Root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $Controller = Join-Path $Root "scripts\granted-auto-auth.ps1"
    & $Controller doctor
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: core doctor failed"
        return
    }
    $Sentinels = @{
        SSH_CLIENT = "doctor-ssh"; SSH_TTY = ""; SSH_CONNECTION = "doctor-connection"
        CI = "doctor-ci"; CODESPACES = ""; CLOUD_SHELL = "doctor-cloud-shell"
    }
    foreach ($Pair in $Sentinels.GetEnumerator()) {
        [System.Environment]::SetEnvironmentVariable($Pair.Key, $Pair.Value, "Process")
    }
    $env:GRANTED_AUTO_AUTH_DRY_PROBE = "1"
    try {
        assume __granted_auto_auth_dry_probe__
        if ($env:ASSUME_STATUS -ne "73") {
            Write-Host "FAIL: PowerShell adapter dry probe failed: status=$env:ASSUME_STATUS"
            return
        }
        foreach ($Pair in $Sentinels.GetEnumerator()) {
            if ([System.Environment]::GetEnvironmentVariable($Pair.Key, "Process") -ne $Pair.Value) {
                Write-Host "FAIL: PowerShell adapter environment restoration failed"
                return
            }
        }
        Write-Host "OK: PowerShell adapter is ready"
    }
    finally {
        Remove-Item Env:GRANTED_AUTO_AUTH_DRY_PROBE -ErrorAction SilentlyContinue
    }
}
