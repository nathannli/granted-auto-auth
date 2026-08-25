# Sources the bash assume wrapper from granted (mirrors fish's source $ASSUME_PATH/assume.fish)
assume() {
	local controller="$HOME/.config/granted-auto-auth/scripts/granted-auto-auth"
	local shim_path="$HOME/.config/granted-auto-auth/scripts/granted-auto-auth-bin"
	local resolved_assumego
	resolved_assumego="$(command -v assumego)" || {
		echo "assume: assumego executable not found" >&2
		return 127
	}
	resolved_assumego="$(realpath "$resolved_assumego")" || return 1
	local real_assumego="$resolved_assumego"
	local deadline
	local shim_executable
	shim_executable="$(realpath "$shim_path/assumego" 2>/dev/null || true)"
	if [[ "$resolved_assumego" == "$shim_executable" ]]; then
		if [[ -z "${GRANTED_AUTO_AUTH_REAL_ASSUMEGO:-}" || -z "${GRANTED_AUTO_AUTH_DEADLINE_NS:-}" ]]; then
			echo "assume: nested automation context is incomplete" >&2
			return 1
		fi
		real_assumego="$GRANTED_AUTO_AUTH_REAL_ASSUMEGO"
		deadline="$GRANTED_AUTO_AUTH_DEADLINE_NS"
	else
		deadline="$(python3 -c 'import time; print(time.monotonic_ns() + 180_000_000_000)' 2>/dev/null)"
		[[ -n "$deadline" ]] || return 1
	fi
	if [[ "$real_assumego" != /* || ! -x "$real_assumego" ]]; then
		echo "assume: resolved assumego executable is invalid" >&2
		return 1
	fi
	local assume_path="${real_assumego%/*}"
	if [[ ! -f "$assume_path/assume" ]]; then
		echo "assume: Granted Bash wrapper not found" >&2
		return 1
	fi

	local automation_enabled=0
	if [[ -x "$controller" ]] && command timeout --signal=KILL 2 "$controller" enabled; then
		local -x GRANTED_AUTO_AUTH_DEADLINE_NS="$deadline"
		local -x GRANTED_AUTO_AUTH_REAL_ASSUMEGO="$real_assumego"
		local -x PATH="$shim_path:$PATH"
		local -x SSH_CLIENT=""
		local -x SSH_TTY=""
		local -x SSH_CONNECTION=""
		local -x CI=""
		local -x CODESPACES=""
		local -x CLOUD_SHELL=""
		automation_enabled=1
	fi
	if [[ -n "${GRANTED_AUTO_AUTH_DRY_PROBE:-}" ]]; then
		if [[ "$GRANTED_AUTO_AUTH_DRY_PROBE" != 1 || $automation_enabled -ne 1 ]]; then
			return 1
		fi
		local active_assumego
		active_assumego="$(realpath "$(command -v assumego)")" || return 1
		if [[ "$active_assumego" != "$shim_executable" || "$GRANTED_AUTO_AUTH_REAL_ASSUMEGO" != "$real_assumego" || ! "$GRANTED_AUTO_AUTH_DEADLINE_NS" =~ ^[0-9]+$ ]]; then
			return 1
		fi
		local name
		for name in SSH_CLIENT SSH_TTY SSH_CONNECTION CI CODESPACES CLOUD_SHELL; do
			[[ -z "${!name}" ]] || return 1
		done
		return 73
	fi

	source "$assume_path/assume" "$@"
}

_granted_auto_auth_supported_platform() {
	local os="$1"
	local distro="$2"
	local shell_name="$3"
	if [[ "$os" == Darwin && "$shell_name" == fish ]]; then
		return 0
	fi
	if [[ "$os" == Linux && "$distro" == ubuntu && ("$shell_name" == fish || "$shell_name" == bash) ]]; then
		return 0
	fi
	return 1
}

granted-auto-auth-doctor() {
	local os
	os="$(uname -s 2>/dev/null)"
	local distro=""
	local os_release="${GRANTED_AUTO_AUTH_OS_RELEASE:-/etc/os-release}"
	if [[ "$os" == Linux && -f "$os_release" ]]; then
		distro="$(sed -n 's/^ID="\{0,1\}\([^" ]*\)"\{0,1\}$/\1/p' "$os_release")"
	fi
	if ! _granted_auto_auth_supported_platform "$os" "$distro" bash; then
		echo "FAIL: unsupported platform: $os/$distro/bash"
		return 1
	fi
	local controller="$HOME/.config/granted-auto-auth/scripts/granted-auto-auth"
	if [[ ! -x "$controller" ]] || ! "$controller" doctor; then
		echo "FAIL: core doctor failed"
		return 1
	fi
	local resolved_assumego
	resolved_assumego="$(command -v assumego)" || {
		echo "FAIL: assumego executable not found"
		return 1
	}
	local real_assumego
	real_assumego="$(realpath "$resolved_assumego")" || return 1
	if [[ ! -x "$real_assumego" || ! -f "${real_assumego%/*}/assume" || ! -x "$HOME/.config/granted-auto-auth/scripts/granted-auto-auth-bin/assumego" ]]; then
		echo "FAIL: adapter path or shim mismatch"
		return 1
	fi
	local -x SSH_CLIENT=doctor-ssh
	local -x SSH_TTY=doctor-tty
	local -x SSH_CONNECTION=doctor-connection
	local -x CI=doctor-ci
	local -x CODESPACES=doctor-codespaces
	local -x CLOUD_SHELL=doctor-cloud-shell
	local -x GRANTED_AUTO_AUTH_DRY_PROBE=1
	assume __granted_auto_auth_dry_probe__
	local probe_status=$?
	if [[ $probe_status -ne 73 || "$SSH_CLIENT" != doctor-ssh || "$SSH_TTY" != doctor-tty || "$SSH_CONNECTION" != doctor-connection || "$CI" != doctor-ci || "$CODESPACES" != doctor-codespaces || "$CLOUD_SHELL" != doctor-cloud-shell ]]; then
		echo "FAIL: adapter dry probe failed: status=$probe_status"
		return 1
	fi
	echo "OK: Bash adapter is ready"
}
