# granted-auto-auth

Headless browser automation for [Granted](https://github.com/fwdcloudsec/granted) AWS IAM Identity Center reauthentication. It completes supported username, password, TOTP, and AWS approval pages while keeping Granted responsible for profiles, SSO tokens, and AWS credentials.

Supported systems:

- macOS with Fish
- Ubuntu with Fish
- Ubuntu with Bash

## Install

Requirements: Git, [uv](https://docs.astral.sh/uv/), Granted v0.39.x, and a compatible Fish or Bash `assume` adapter. On Ubuntu, the user's D-Bus session must expose an unlocked default Secret Service collection owned by `gnome-keyring-daemon`.

Clone the repository into its expected configuration directory:

```sh
git clone https://github.com/nathannli/granted-auto-auth.git "$HOME/.config/granted-auto-auth"
```

Add the repository's `scripts` directory to `PATH`.

Fish, on macOS or Ubuntu:

```fish
fish_add_path "$HOME/.config/granted-auto-auth/scripts"
```

Bash, on Ubuntu: add this line to `$HOME/.bashrc`, then start a new shell or run `source "$HOME/.bashrc"`:

```bash
export PATH="$HOME/.config/granted-auto-auth/scripts:$PATH"
```

Confirm the command is available:

```sh
command -v granted-auto-browser
```

Then create the credential file, configure Granted, and install Chromium by following the [complete installation guide](docs/granted-auto-auth.md#installation).

> Adding this repository to `PATH` exposes the controller. Automatic `assume` reauthentication also requires a shell adapter that supplies the shared deadline and verified `assumego` path. The adapter belongs to the user's Fish or Bash configuration and is intentionally not installed by this repository.

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
