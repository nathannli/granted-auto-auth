# Granted automatic reauthentication

`granted-auto-auth` is a shell-neutral controller and headless browser sidecar for Granted v0.39.x. Granted still owns AWS profile selection, IAM Identity Center tokens, and role credentials. This project automates only the supported browser reauthentication flow.

## Supported systems

| Operating system | Shell | Status |
| --- | --- | --- |
| macOS | Fish | Supported |
| Ubuntu Linux | Fish | Supported |
| Ubuntu Linux | Bash | Supported |

Other Linux distributions, macOS with Bash, and other shells are outside the supported matrix. The core controller rejects unsupported operating systems; the external shell adapter is responsible for rejecting unsupported shell combinations.

## Requirements

- Git
- [uv](https://docs.astral.sh/uv/) with access to Python 3.12 or newer
- [Granted](https://docs.commonfate.io/granted/getting-started) v0.39.x, with both `granted` and `assumego` on `PATH`
- A Fish or Bash adapter implementing the [shell integration contract](#shell-integration-contract)
- Network access during `install` to resolve the locked script environment and download Chromium
- On Ubuntu: `busctl`, a user D-Bus session, and an unlocked default Secret Service collection owned by the user's `gnome-keyring-daemon`

Authentication runs from the locked local environment with no dependency downloads after installation.

## Installation

### 1. Clone the repository

The repository and private configuration files intentionally share `$HOME/.config/granted-auto-auth`. The private files are ignored by Git.

```sh
git clone https://github.com/nathannli/granted-auto-auth.git "$HOME/.config/granted-auto-auth"
```

For an existing clone, update it without rewriting local state:

```sh
git -C "$HOME/.config/granted-auto-auth" pull --ff-only
```

### 2. Add the controller to `PATH`

The executable is in the repository's `scripts` directory, not its root.

Fish on macOS or Ubuntu:

```fish
fish_add_path "$HOME/.config/granted-auto-auth/scripts"
```

`fish_add_path` persists the path in Fish's universal variables. Open a new shell, or use the current shell immediately.

Bash on Ubuntu: add the following line to `$HOME/.bashrc`:

```bash
export PATH="$HOME/.config/granted-auto-auth/scripts:$PATH"
```

Load the change:

```bash
source "$HOME/.bashrc"
```

Verify the resolved command:

```sh
command -v granted-auto-browser
```

It should resolve to:

```text
$HOME/.config/granted-auto-auth/scripts/granted-auto-browser
```

### 3. Create the credential file

```sh
install -d -m 700 "$HOME/.config/granted-auto-auth"
cp "$HOME/.config/granted-auto-auth/examples/granted-auto-auth.credentials.toml" \
  "$HOME/.config/granted-auto-auth/credentials.toml"
chmod 600 "$HOME/.config/granted-auto-auth/credentials.toml"
```

Edit `$HOME/.config/granted-auto-auth/credentials.toml`:

```toml
username = "user@example.com"
password = "replace-me"
totp_secret = "BASE32SECRET"
idp = "aws_identity_center"
```

| Field | Meaning |
| --- | --- |
| `username` | IAM Identity Center sign-in username. |
| `password` | IAM Identity Center sign-in password. |
| `totp_secret` | Base32 `secret=` value from the `otpauth://totp/...` URI, not the rotating six-digit code. Spaces and hyphens are accepted and normalized. |
| `idp` | Authentication adapter. The only supported value is `aws_identity_center`. |

The directory must be owned by the current user with mode `0700`. The credential file must be a regular, non-symlink file owned by the current user with mode `0600` or stricter.

The credential file is plaintext protected by local file ownership and permissions; it is not stored in the system keyring. Use this only on a trusted, encrypted workstation account. Granted's SSO-token cache remains separate and uses its configured secure-storage backend.

### 4. Configure Granted

The controller requires authorization-code flow and Granted's credential-process cache:

```sh
granted settings set --setting UseAuthorizationCode --value true
granted settings set --setting DisableCredentialProcessCache --value false
```

`install` changes only `CustomSSOBrowserPath`. It records the previous value so `uninstall` can restore it.

#### How Granted configuration changes

Granted stores its settings in `$HOME/.granted/config`. The controller does not rewrite that TOML file itself. It asks Granted to update one setting with the equivalent of:

```sh
granted settings set \
  --setting CustomSSOBrowserPath \
  --value /absolute/path/to/granted-auto-auth/scripts/granted_auto_browser.py
```

Granted then persists an absolute path like this:

```toml
CustomSSOBrowserPath = "/Users/alice/.config/granted-auto-auth/scripts/granted_auto_browser.py"
```

The exact home-directory prefix differs by operating system. The stored value is always expanded to an absolute path; `$HOME` and `~` are not written literally.

The installation sequence is:

1. Read the current `CustomSSOBrowserPath` from `$HOME/.granted/config`.
2. Save that previous value in `$HOME/.config/granted-auto-auth/install.toml`.
3. Provision the locked runtime and Chromium before changing Granted.
4. Ask `granted settings set` to write the sidecar's absolute path.
5. Read `$HOME/.granted/config` again and require the persisted value to match exactly.
6. Mark the install state as configured only after verification succeeds.

If installation fails after changing Granted, rollback restores the saved value. `uninstall` first marks its state as uninstalling, asks Granted to restore the saved `CustomSSOBrowserPath`, verifies the result, and only then removes `install.toml`. If another tool or user has changed `CustomSSOBrowserPath` since installation, `uninstall` refuses to overwrite that unrelated value.

The controller only validates `UseAuthorizationCode` and `DisableCredentialProcessCache` during `doctor`; `install` does not change them. The explicit setup commands above remain user-controlled changes.

### 5. Install the browser runtime

```sh
granted-auto-browser install
granted-auto-browser doctor
```

`install` verifies the locked PEP 723 environment, downloads the exact Playwright Chromium revision, writes `$HOME/.config/granted-auto-auth/install.toml`, and configures the sidecar as Granted's custom SSO browser. A successful doctor ends with:

```text
OK: granted-auto-auth is ready
```

### 6. Confirm the shell adapter

Adding `scripts` to `PATH` installs the controller but does not replace Granted's shell function. Before authentication, the Fish or Bash adapter must satisfy the contract below. Run its own readiness check if it provides one.

## Shell integration contract

This repository is intentionally independent of Fish and Bash dotfile repositories. A compatible external `assume` adapter must:

1. Resolve the real `assumego` executable before prepending the private shim directory.
2. Export that absolute path as `GRANTED_AUTO_AUTH_REAL_ASSUMEGO`.
3. Export one absolute monotonic deadline as `GRANTED_AUTO_AUTH_DEADLINE_NS`; the supported overall timeout is 180 seconds.
4. Prepend `$HOME/.config/granted-auto-auth/scripts/granted-auto-auth-bin` to `PATH` for only the `assume` call.
5. Reuse an existing deadline for nested calls.
6. Restore the caller's `PATH` and `GRANTED_AUTO_AUTH_*` environment after the call.
7. Preserve Granted's exit status and stop on deadline exit `124` rather than retrying.

The private `assumego` shim and browser sidecar are implementation details. Do not invoke them directly.

## Controller command reference

Syntax:

```text
granted-auto-browser doctor|enabled|install|uninstall
```

The controller accepts one command. It has no short options, long options, positional values, or combined commands.

### `install`

```sh
granted-auto-browser install
```

- Requires network access for initial dependency and Chromium installation.
- Verifies the script lock before modifying Granted.
- Saves the current `CustomSSOBrowserPath`.
- Installs the matching Chromium revision.
- Sets `CustomSSOBrowserPath` to the repository sidecar.
- Rolls back the Granted setting if installation fails.
- Recovers safely from known interrupted installation phases.
- Is idempotent. When already enabled, it revalidates and resynchronizes the locked runtime.
- Returns `0` on success and `1` on failure.

### `enabled`

```sh
granted-auto-browser enabled
```

Silent and authentication-free. It returns `0` only when all of these are healthy:

- configured install state and exact Playwright version;
- Granted custom-browser path;
- sidecar, lock file, and matching executable Chromium revision;
- supported process backend;
- on Ubuntu, the Secret Service owner and unlocked default collection.

It returns `1` for disabled, incomplete, stale, unsupported, or unhealthy state. Use `doctor` to learn why.

### `doctor`

```sh
granted-auto-browser doctor
```

Runs authentication-free diagnostics for:

- credential file presence, fields, ownership, and permissions;
- Granted v0.39.x availability;
- `UseAuthorizationCode=true`;
- `DisableCredentialProcessCache=false`;
- current installation and Chromium state;
- macOS `libproc` or Ubuntu `/proc` support;
- Ubuntu Secret Service availability, owner, and default-collection lock state;
- dedicated browser-profile ownership and permissions;
- legacy inline SSO profiles and container fallback warnings.

`FAIL:` lines produce exit `1`. `WARN:` lines are informational and do not change a successful exit. A healthy result prints `OK: granted-auto-auth is ready` and exits `0`.

### `uninstall`

```sh
granted-auto-browser uninstall
```

- Refuses to overwrite a Granted browser setting that no longer matches this installation.
- Restores the `CustomSSOBrowserPath` saved by `install`.
- Removes `$HOME/.config/granted-auto-auth/install.toml`.
- Preserves `$HOME/.config/granted-auto-auth/credentials.toml`.
- Preserves downloaded Chromium and `$HOME/.local/share/granted-auto-auth/browser` for recovery or later reuse.
- Returns `0` on success and `1` on failure.

### Usage errors and exit statuses

| Exit | Meaning |
| --- | --- |
| `0` | Command succeeded, doctor is healthy, or automation is enabled. |
| `1` | Controller operation failed, doctor found a failure, or automation is not enabled. |
| `2` | Missing, extra, or unknown controller argument. |
| `124` | The external shell adapter's 180-second authentication deadline expired. Do not loop or immediately retry. |

The browser sidecar has additional internal exit codes and structured events. They are consumed by the integration and are not a public command interface.

## Authentication usage

Export credentials into the current interactive shell:

```sh
assume <profile> --use-authorization-code
```

Run one command with credentials confined to the child process:

```sh
assume <profile> --use-authorization-code --exec -- aws sts get-caller-identity
```

Relevant Granted options:

| Option | Behavior |
| --- | --- |
| `<profile>` | Exact AWS profile to assume. |
| `--use-authorization-code` | Selects the PKCE authorization-code flow required by this automation. |
| `--exec -- <command>` | Runs one command with temporary credentials instead of exporting them into the caller. Preferred for agents. |
| `--no-cache` | Forces Granted to bypass cached session credentials. Use only for a specifically stale cache or an intentional fresh-login test. |

These are Granted options, not controller options. Run `assumego --help` for Granted's complete option list.

A valid Granted cache returns immediately without launching Chromium. An expired session opens the persistent headless browser profile and attempts username, password, TOTP, and AWS access approval.

## Files and state

| Path | Purpose | Removed by `uninstall`? |
| --- | --- | --- |
| `$HOME/.config/granted-auto-auth/credentials.toml` | Private IdP credentials and TOTP seed. | No |
| `$HOME/.config/granted-auto-auth/install.toml` | Installation phase, previous browser setting, and Chromium identity. | Yes |
| `$HOME/.local/share/granted-auto-auth/browser/` | Persistent dedicated Chromium profile. | No |
| `$HOME/.local/share/granted-auto-auth/browser.lock` | Single-browser-process lock. | No |
| `$HOME/.config/granted-auto-auth/scripts/granted-auto-browser` | Public controller command. | No |
| `$HOME/.config/granted-auto-auth/scripts/granted_auto_browser.py` | Granted custom-browser sidecar; internal. | No |
| `$HOME/.config/granted-auto-auth/scripts/granted-auto-auth-bin/assumego` | Deadline shim; internal. | No |

Do not commit `credentials.toml` or `install.toml`. Do not inspect or publish browser URLs, process arguments, SSO cache contents, TOTP values, or AWS credentials.

## Supported and unsupported browser flows

Supported:

- IAM Identity Center username
- password
- TOTP
- AWS access approval
- PKCE callback completion

Fails closed and requires human action:

- CAPTCHA
- WebAuthn or security keys
- push approval
- device compliance
- password changes or resets
- account recovery
- unknown authentication challenges

Containers may cause Granted to fall back to device flow. The controller reports this as a warning because device approval requires human action.

## Troubleshooting

Start with:

```sh
granted-auto-browser doctor
```

Common results:

- `installation is not enabled`: run `granted-auto-browser install`, then rerun doctor.
- `Granted v0.39.x is required`: install a supported Granted release.
- `UseAuthorizationCode must be true`: set the Granted setting shown in the installation section.
- `DisableCredentialProcessCache must be false`: re-enable Granted's cache with the setting shown above.
- `Secret Service is unavailable`: ensure the Ubuntu user D-Bus session and `gnome-keyring-daemon` are running.
- `Secret Service default collection is locked`: unlock the user's default keyring collection, then rerun doctor.
- `legacy inline SSO profiles detected`: migrate those AWS profiles to shared `[sso-session ...]` configuration when practical. This is a warning, not a failure.
- Exit `124`: the shared hard deadline expired. Stop rather than starting a retry loop.
- `unsupported_challenge`: complete the unsupported step manually; do not weaken the browser selectors or bypass the challenge.

Preserve Granted's encrypted cache and the browser profile during troubleshooting. A cache hit is expected and proves reuse; deleting `$HOME/.aws/cli`, `$HOME/.aws/sso`, or the browser profile is not a normal installation or repair step.
