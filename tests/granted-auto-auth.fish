#!/usr/bin/env fish

set -l repo_dir (path resolve (path dirname (status filename))/..)
source "$repo_dir/adapters/fish/assume.fish"
functions -c assume granted_auto_auth_assume

set -g failures 0
set -g mac_fixture 0
set -g unlock_calls 0

function is_mac
    test $mac_fixture -eq 1
end

function unlockkeychain
    set -g unlock_calls (math $unlock_calls + 1)
    echo unlock >> "$HOME/assume-order"
end

function granted_auto_auth_pre_assume
    if is_mac
        unlockkeychain
    end
end

function check -a expected actual label
    if test "$expected" != "$actual"
        echo "FAIL: $label: expected '$expected', got '$actual'" >&2
        set -g failures (math $failures + 1)
    end
end

set -l fixture (mktemp -d)
set -l original_home "$HOME"
set -l original_path $PATH
set -gx HOME "$fixture/home"
set -l real_bin "$fixture/real/bin"
set -l core_bin "$HOME/.config/granted-auto-auth/scripts"
mkdir -p "$real_bin" "$core_bin/granted-auto-auth-bin"

printf '%s\n' '#!/bin/sh' 'printf "assume\\n" >> "$HOME/assume-order"' 'printf "%s|%s|%s|%s|%s\\n" "$*" "$GRANTED_AUTO_AUTH_DEADLINE_NS" "$GRANTED_AUTO_AUTH_REAL_ASSUMEGO" "$SSH_CLIENT" "$CI" >> "$HOME/calls"' 'if [ -n "$GRANTED_AUTO_AUTH_DEADLINE_NS" ]; then printf "browser\\n" >> "$HOME/browser"; fi' 'exit "${REAL_STATUS:-7}"' > "$real_bin/assumego"
printf '%s\n' 'assumego $argv' 'return $status' > "$real_bin/assume.fish"
printf '%s\n' '#!/bin/sh' 'printf "controller:%s\\n" "$*" >> "$HOME/controller"' 'exit "${CONTROLLER_STATUS:-0}"' > "$core_bin/granted-auto-auth"
printf '%s\n' '#!/bin/sh' 'printf "shim\\n" >> "$HOME/shim"' 'exec "$GRANTED_AUTO_AUTH_REAL_ASSUMEGO" "$@"' > "$core_bin/granted-auto-auth-bin/assumego"
chmod +x "$real_bin/assumego" "$core_bin/granted-auto-auth" "$core_bin/granted-auto-auth-bin/assumego"
set -gx PATH "$real_bin" /usr/bin /bin
set -gx SSH_CLIENT caller-ssh
set -gx CI caller-ci

set -g mac_fixture 1
granted_auto_auth_assume adev
check 7 $status "enabled target status"
check 1 $unlock_calls "macOS keychain unlock count"
check "unlock assume" (string join ' ' (cat "$HOME/assume-order")) "macOS keychain unlock order"
set -g mac_fixture 0
check controller:enabled (string trim (cat "$HOME/controller")) "readiness probe"
check shim (string trim (cat "$HOME/shim")) "private shim resolution"
check browser (string trim (cat "$HOME/browser")) "cache-miss browser launch"
set -l call_fields (string split '|' (string trim (cat "$HOME/calls")))
check adev "$call_fields[1]" "enabled arguments"
check (path resolve "$real_bin/assumego") "$call_fields[3]" "real path export"
check "" "$call_fields[4]" "SSH mask"
check "" "$call_fields[5]" "CI mask"
check caller-ssh "$SSH_CLIENT" "caller SSH restoration"
check caller-ci "$CI" "caller CI restoration"

set -g mac_fixture 1
set -gx GRANTED_AUTO_AUTH_DRY_PROBE 1
granted_auto_auth_assume __granted_auto_auth_dry_probe__
check 73 $status "macOS dry probe status"
check 1 $unlock_calls "macOS dry probe skips keychain unlock"
set -e GRANTED_AUTO_AUTH_DRY_PROBE
set -g mac_fixture 0

functions -e assume
functions -c granted_auto_auth_assume assume
check 0 (_granted_auto_auth_supported_platform Darwin "" fish; echo $status) "macOS Fish support"
check 1 (_granted_auto_auth_supported_platform Darwin "" bash; echo $status) "macOS Bash rejection"
check 0 (_granted_auto_auth_supported_platform Linux ubuntu fish; echo $status) "Ubuntu Fish support"
check 1 (_granted_auto_auth_supported_platform Linux fedora fish; echo $status) "non-Ubuntu rejection"
check 1 (_granted_auto_auth_supported_platform Linux ubuntu zsh; echo $status) "unsupported shell rejection"

granted-auto-auth-doctor >/dev/null
check 0 $status "Fish doctor success"
chmod -x "$core_bin/granted-auto-auth-bin/assumego"
granted-auto-auth-doctor >/dev/null
check 1 $status "Fish doctor shim mismatch"
chmod +x "$core_bin/granted-auto-auth-bin/assumego"
set -l doctor_path $PATH
set -gx PATH "$core_bin/granted-auto-auth-bin" "$real_bin" /usr/bin /bin
set -gx GRANTED_AUTO_AUTH_DRY_PROBE 1
set -e GRANTED_AUTO_AUTH_DEADLINE_NS
set -e GRANTED_AUTO_AUTH_REAL_ASSUMEGO
assume __granted_auto_auth_dry_probe__ 2>/dev/null
check 1 $status "Fish doctor deadline and real-path omission"
set -e GRANTED_AUTO_AUTH_DRY_PROBE
set -gx PATH $doctor_path
set -gx CONTROLLER_STATUS 1
granted-auto-auth-doctor >/dev/null
check 1 $status "Fish doctor core failure"
set -e CONTROLLER_STATUS

rm -f "$HOME/calls" "$HOME/shim" "$HOME/browser"
set -gx PATH "$core_bin/granted-auto-auth-bin" "$real_bin" /usr/bin /bin
set -gx GRANTED_AUTO_AUTH_DEADLINE_NS 424242
set -gx GRANTED_AUTO_AUTH_REAL_ASSUMEGO (path resolve "$real_bin/assumego")
granted_auto_auth_assume atest
check 7 $status "nested target status"
set -l nested_fields (string split '|' (string trim (cat "$HOME/calls")))
check 424242 "$nested_fields[2]" "nested deadline reuse"
check (path resolve "$real_bin/assumego") "$nested_fields[3]" "nested real path reuse"

rm -f "$HOME/calls" "$HOME/shim" "$HOME/browser"
set -gx PATH "$real_bin" /usr/bin /bin
set -e GRANTED_AUTO_AUTH_DEADLINE_NS
set -e GRANTED_AUTO_AUTH_REAL_ASSUMEGO
set -gx REAL_STATUS 130
granted_auto_auth_assume network
check 130 $status "signal status"
check caller-ssh "$SSH_CLIENT" "signal SSH restoration"
check caller-ci "$CI" "signal CI restoration"
set -e REAL_STATUS

rm -f "$HOME/calls" "$HOME/shim"
set -gx CONTROLLER_STATUS 1
granted_auto_auth_assume sdev
check 7 $status "disabled target status"
check sdev (string split '|' (string trim (cat "$HOME/calls")))[1] "disabled arguments"
check false (test -e "$HOME/shim"; and echo true; or echo false) "disabled shim bypass"
check caller-ssh "$SSH_CLIENT" "disabled SSH preservation"
check caller-ci "$CI" "disabled CI preservation"

set -e CONTROLLER_STATUS
set -e SSH_CLIENT
set -e CI
set -gx HOME "$original_home"
set -gx PATH $original_path
rm -rf "$fixture"

exit $failures
