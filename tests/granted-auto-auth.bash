#!/usr/bin/env bash

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_dir/adapters/bash/assume.bash"
eval "$(declare -f assume | sed '1s/^assume /granted_auto_auth_assume /')"

failures=0

check() {
	local expected="$1"
	local actual="$2"
	local label="$3"
	if [[ "$expected" != "$actual" ]]; then
		echo "FAIL: $label: expected '$expected', got '$actual'" >&2
		((failures++))
	fi
}

fixture="$(mktemp -d)"
original_home="$HOME"
original_path="$PATH"
export HOME="$fixture/home"
real_bin="$fixture/real/bin"
core_bin="$HOME/.config/granted-auto-auth/scripts"
mkdir -p "$real_bin" "$core_bin/granted-auto-auth-bin"

printf '%s\n' '#!/bin/sh' 'printf "%s|%s|%s|%s|%s\\n" "$*" "$GRANTED_AUTO_AUTH_DEADLINE_NS" "$GRANTED_AUTO_AUTH_REAL_ASSUMEGO" "$SSH_CLIENT" "$CI" >> "$HOME/calls"' 'if [ -n "$GRANTED_AUTO_AUTH_DEADLINE_NS" ]; then printf "browser\\n" >> "$HOME/browser"; fi' 'exit "${REAL_STATUS:-7}"' > "$real_bin/assumego"
printf '%s\n' 'assumego "$@"' > "$real_bin/assume"
printf '%s\n' '#!/bin/sh' 'printf "controller:%s\\n" "$*" >> "$HOME/controller"' 'exit "${CONTROLLER_STATUS:-0}"' > "$core_bin/granted-auto-browser"
printf '%s\n' '#!/bin/sh' 'printf "shim\\n" >> "$HOME/shim"' 'exec "$GRANTED_AUTO_AUTH_REAL_ASSUMEGO" "$@"' > "$core_bin/granted-auto-auth-bin/assumego"
printf '%s\n' '#!/bin/sh' 'shift 2' 'exec "$@"' > "$real_bin/timeout"
chmod +x "$real_bin/assumego" "$core_bin/granted-auto-browser" "$core_bin/granted-auto-auth-bin/assumego" "$real_bin/timeout"
export PATH="$real_bin:/usr/bin:/bin"
export SSH_CLIENT=caller-ssh
export CI=caller-ci

granted_auto_auth_assume adev
check 7 "$?" "enabled target status"
check controller:enabled "$(<"$HOME/controller")" "readiness probe"
check shim "$(<"$HOME/shim")" "private shim resolution"
check browser "$(<"$HOME/browser")" "cache-miss browser launch"
IFS='|' read -r call_args call_deadline call_real call_ssh call_ci < "$HOME/calls"
check adev "$call_args" "enabled arguments"
check "$(realpath "$real_bin/assumego")" "$call_real" "real path export"
check "" "$call_ssh" "SSH mask"
check "" "$call_ci" "CI mask"
check caller-ssh "$SSH_CLIENT" "caller SSH restoration"
check caller-ci "$CI" "caller CI restoration"

eval "$(declare -f granted_auto_auth_assume | sed '1s/^granted_auto_auth_assume /assume /')"
_granted_auto_auth_supported_platform Darwin "" fish
check 0 "$?" "macOS Fish support"
_granted_auto_auth_supported_platform Darwin "" bash
check 1 "$?" "macOS Bash rejection"
_granted_auto_auth_supported_platform Linux ubuntu bash
check 0 "$?" "Ubuntu Bash support"
_granted_auto_auth_supported_platform Linux fedora bash
check 1 "$?" "non-Ubuntu rejection"
_granted_auto_auth_supported_platform Linux ubuntu zsh
check 1 "$?" "unsupported shell rejection"

printf '%s\n' 'ID=ubuntu' > "$HOME/os-release"
export GRANTED_AUTO_AUTH_OS_RELEASE="$HOME/os-release"
uname() { printf '%s\n' Linux; }
granted-auto-auth-doctor >/dev/null
check 0 "$?" "Bash doctor success"
chmod -x "$core_bin/granted-auto-auth-bin/assumego"
granted-auto-auth-doctor >/dev/null
check 1 "$?" "Bash doctor shim mismatch"
chmod +x "$core_bin/granted-auto-auth-bin/assumego"
doctor_path="$PATH"
export PATH="$core_bin/granted-auto-auth-bin:$real_bin:/usr/bin:/bin"
export GRANTED_AUTO_AUTH_DRY_PROBE=1
unset GRANTED_AUTO_AUTH_DEADLINE_NS GRANTED_AUTO_AUTH_REAL_ASSUMEGO
assume __granted_auto_auth_dry_probe__ 2>/dev/null
check 1 "$?" "Bash doctor deadline and real-path omission"
unset GRANTED_AUTO_AUTH_DRY_PROBE
export PATH="$doctor_path"
export CONTROLLER_STATUS=1
granted-auto-auth-doctor >/dev/null
check 1 "$?" "Bash doctor core failure"
unset CONTROLLER_STATUS GRANTED_AUTO_AUTH_OS_RELEASE
unset -f uname

rm -f "$HOME/calls" "$HOME/shim" "$HOME/browser"
export PATH="$core_bin/granted-auto-auth-bin:$real_bin:/usr/bin:/bin"
export GRANTED_AUTO_AUTH_DEADLINE_NS=424242
export GRANTED_AUTO_AUTH_REAL_ASSUMEGO="$(realpath "$real_bin/assumego")"
granted_auto_auth_assume atest
check 7 "$?" "nested target status"
IFS='|' read -r call_args call_deadline call_real call_ssh call_ci < "$HOME/calls"
check 424242 "$call_deadline" "nested deadline reuse"
check "$(realpath "$real_bin/assumego")" "$call_real" "nested real path reuse"

rm -f "$HOME/calls" "$HOME/shim" "$HOME/browser"
export PATH="$real_bin:/usr/bin:/bin"
unset GRANTED_AUTO_AUTH_DEADLINE_NS GRANTED_AUTO_AUTH_REAL_ASSUMEGO
export REAL_STATUS=130
granted_auto_auth_assume network
check 130 "$?" "signal status"
check caller-ssh "$SSH_CLIENT" "signal SSH restoration"
check caller-ci "$CI" "signal CI restoration"
unset REAL_STATUS

rm -f "$HOME/calls" "$HOME/shim" "$HOME/browser"
export CONTROLLER_STATUS=1
granted_auto_auth_assume sdev
check 7 "$?" "disabled target status"
IFS='|' read -r call_args call_deadline call_real call_ssh call_ci < "$HOME/calls"
check sdev "$call_args" "disabled arguments"
check false "$([[ -e "$HOME/shim" ]] && echo true || echo false)" "disabled shim bypass"
check caller-ssh "$SSH_CLIENT" "disabled SSH preservation"
check caller-ci "$CI" "disabled CI preservation"

unset CONTROLLER_STATUS SSH_CLIENT CI
export HOME="$original_home"
export PATH="$original_path"
rm -rf "$fixture"

exit "$failures"
