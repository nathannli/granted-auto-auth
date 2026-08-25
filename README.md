# granted-auto-auth

Headless browser automation for [Granted](https://github.com/fwdcloudsec/granted) AWS IAM Identity Center reauthentication. It completes supported username, password, TOTP, and AWS approval pages while keeping Granted responsible for profiles, SSO tokens, and AWS credentials.

Supported systems:

- macOS with Fish
- Ubuntu with Fish
- Ubuntu with Bash

## Requirements
- [uv](https://docs.astral.sh/uv/), 
- Granted v0.39.x
- Fish or Bash configured to source this repository's `assume` adapter.
- On Ubuntu, the user's D-Bus session must expose an unlocked default Secret Service collection owned by `gnome-keyring-daemon`.

## Install

Clone the repository into its expected configuration directory:

```sh
git clone https://github.com/nathannli/granted-auto-auth.git "$HOME/.config/granted-auto-auth"
```

Add the repository's `scripts` directory to `PATH`.

Fish, on macOS or Ubuntu:

```fish
fish_add_path "$HOME/.config/granted-auto-auth/scripts"
source "$HOME/.config/granted-auto-auth/adapters/fish/assume.fish"
```

Bash, on Ubuntu: add these lines to `$HOME/.bashrc`, then start a new shell or run `source "$HOME/.bashrc"`:

```bash
export PATH="$HOME/.config/granted-auto-auth/scripts:$PATH"
source "$HOME/.config/granted-auto-auth/adapters/bash/assume.bash"
```

Confirm the command is available:

```sh
command -v granted-auto-browser
```

Then create the credential file, configure Granted, and install Chromium by following the [complete installation guide](docs/granted-auto-auth.md#installation).

Adding `scripts` to `PATH` exposes the controller. Sourcing the matching adapter defines `assume` and `granted-auto-auth-doctor` in the current shell. The standalone repository owns this generic integration; personal profile aliases and system-specific hooks may remain in separate dotfiles.

During installation, the controller uses `granted settings set` to change only `CustomSSOBrowserPath` in `$HOME/.granted/config`. It saves the previous value in `$HOME/.config/granted-auto-auth/install.toml`, verifies that Granted persisted the new absolute sidecar path, and restores the saved value during `uninstall`. See [How Granted configuration changes](docs/granted-auto-auth.md#how-granted-configuration-changes).

## Commands

`granted-auto-browser` accepts exactly one command and no flags:

| Command | What it does |
| --- | --- |
| `granted-auto-browser install` | Installs the locked Python environment and matching Chromium, saves the previous Granted custom-browser setting, and configures the headless sidecar. Safe to repeat; a healthy repeat install verifies and repairs the locked runtime. |
| `granted-auto-browser enabled` | Performs a silent, authentication-free readiness check. Exit status `0` means ready; `1` means disabled or unhealthy. Intended for scripts and shell adapters. |
| `granted-auto-browser doctor` | Prints non-secret diagnostics for credentials, Granted settings/version, install state, Chromium, process support, browser-profile permissions, and the Ubuntu Secret Service. Exit status `0` means ready; `1` means one or more `FAIL:` checks. `WARN:` lines do not fail readiness. |
| `granted-auto-browser uninstall` | Restores the previous Granted custom-browser setting and removes install state. Preserves downloaded Chromium, credentials, and the browser profile. |

Any missing, extra, or unknown argument prints usage and exits `2`.

## Use

```sh
assume <profile> --use-authorization-code
```

For an agent or one command, keep credentials scoped to the child process:

```sh
assume <profile> --use-authorization-code --exec -- aws sts get-caller-identity
```

A valid Granted cache returns without browser automation. An expired session launches the headless sidecar. See the [full command, configuration, security, and troubleshooting reference](docs/granted-auto-auth.md).
