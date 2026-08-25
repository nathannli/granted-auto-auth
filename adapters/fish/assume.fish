function assume
    set -l controller "$HOME/.config/granted-auto-auth/scripts/granted-auto-browser"
    set -l shim_path "$HOME/.config/granted-auto-auth/scripts/granted-auto-auth-bin"
    set -l resolved_assumego (command -s assumego)
    if test -z "$resolved_assumego"
        echo "assume: assumego executable not found" >&2
        return 127
    end
    set -l real_assumego (path resolve "$resolved_assumego")
    set -l shim_executable (path resolve "$shim_path/assumego")
    set -l deadline
    if test "$real_assumego" = "$shim_executable"
        if not set -q GRANTED_AUTO_AUTH_REAL_ASSUMEGO; or not set -q GRANTED_AUTO_AUTH_DEADLINE_NS
            echo "assume: nested automation context is incomplete" >&2
            return 1
        end
        set real_assumego "$GRANTED_AUTO_AUTH_REAL_ASSUMEGO"
        set deadline "$GRANTED_AUTO_AUTH_DEADLINE_NS"
    else
        set deadline (python3 -c 'import time; print(time.monotonic_ns() + 180_000_000_000)' 2>/dev/null)
        or return 1
    end
    if not string match -qr '^/' -- "$real_assumego"; or not test -x "$real_assumego"
        echo "assume: resolved assumego executable is invalid" >&2
        return 1
    end
    set -l assume_path (path dirname "$real_assumego")
    if not test -f "$assume_path/assume.fish"
        echo "assume: Granted Fish wrapper not found" >&2
        return 1
    end
    set -f automation_enabled 0
    if test -x "$controller"; and python3 -c 'import subprocess,sys; p=sys.argv[1:];
try: r=subprocess.run(p, timeout=2)
except (OSError, subprocess.TimeoutExpired): sys.exit(1)
sys.exit(r.returncode)' "$controller" enabled
        set -fx GRANTED_AUTO_AUTH_DEADLINE_NS "$deadline"
        set -fx GRANTED_AUTO_AUTH_REAL_ASSUMEGO "$real_assumego"
        set -fx PATH "$shim_path" $PATH
        set -fx SSH_CLIENT ""
        set -fx SSH_TTY ""
        set -fx SSH_CONNECTION ""
        set -fx CI ""
        set -fx CODESPACES ""
        set -fx CLOUD_SHELL ""
        set -f automation_enabled 1
    end
    if set -q GRANTED_AUTO_AUTH_DRY_PROBE
        if test "$GRANTED_AUTO_AUTH_DRY_PROBE" != 1; or test $automation_enabled -ne 1
            return 1
        end
        set -l active_assumego (path resolve (command -s assumego))
        if test "$active_assumego" != "$shim_executable"; or test "$GRANTED_AUTO_AUTH_REAL_ASSUMEGO" != "$real_assumego"; or not string match -qr '^[0-9]+$' -- "$GRANTED_AUTO_AUTH_DEADLINE_NS"
            return 1
        end
        for name in SSH_CLIENT SSH_TTY SSH_CONNECTION CI CODESPACES CLOUD_SHELL
            if test -n "$$name"
                return 1
            end
        end
        return 73
    end
    if functions -q granted_auto_auth_pre_assume
        granted_auto_auth_pre_assume
    end
    source "$assume_path/assume.fish" $argv
end

function _granted_auto_auth_supported_platform -a os distro shell_name
    if test "$os" = Darwin; and test "$shell_name" = fish
        return 0
    end
    if test "$os" = Linux; and test "$distro" = ubuntu; and contains -- "$shell_name" fish bash
        return 0
    end
    return 1
end

function granted-auto-auth-doctor
    set -l os (uname -s 2>/dev/null)
    set -l distro
    set -l os_release "$GRANTED_AUTO_AUTH_OS_RELEASE"
    if test -z "$os_release"
        set os_release /etc/os-release
    end
    if test "$os" = Linux; and test -f "$os_release"
        set distro (string replace -r '^ID="?([^" ]+)"?$' '$1' (string match -r '^ID=.*' (cat "$os_release")))
    end
    if not _granted_auto_auth_supported_platform "$os" "$distro" fish
        echo "FAIL: unsupported platform: $os/$distro/fish"
        return 1
    end
    set -l controller "$HOME/.config/granted-auto-auth/scripts/granted-auto-browser"
    if not test -x "$controller"; or not "$controller" doctor
        echo "FAIL: core doctor failed"
        return 1
    end
    set -l resolved_assumego (command -s assumego)
    if test -z "$resolved_assumego"
        echo "FAIL: assumego executable not found"
        return 1
    end
    set -l real_assumego (path resolve "$resolved_assumego")
    if not test -x "$real_assumego"; or not test -f (path dirname "$real_assumego")/assume.fish; or not test -x "$HOME/.config/granted-auto-auth/scripts/granted-auto-auth-bin/assumego"
        echo "FAIL: adapter path or shim mismatch"
        return 1
    end
    set -fx SSH_CLIENT doctor-ssh
    set -fx SSH_TTY doctor-tty
    set -fx SSH_CONNECTION doctor-connection
    set -fx CI doctor-ci
    set -fx CODESPACES doctor-codespaces
    set -fx CLOUD_SHELL doctor-cloud-shell
    set -fx GRANTED_AUTO_AUTH_DRY_PROBE 1
    assume __granted_auto_auth_dry_probe__
    set -l probe_status $status
    if test $probe_status -ne 73; or test "$SSH_CLIENT" != doctor-ssh; or test "$SSH_TTY" != doctor-tty; or test "$SSH_CONNECTION" != doctor-connection; or test "$CI" != doctor-ci; or test "$CODESPACES" != doctor-codespaces; or test "$CLOUD_SHELL" != doctor-cloud-shell
        echo "FAIL: adapter dry probe failed: status=$probe_status"
        return 1
    end
    echo "OK: Fish adapter is ready"
end
