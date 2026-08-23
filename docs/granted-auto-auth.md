# Granted automatic reauthentication

`assume <profile>` can complete AWS IAM Identity Center username, password, TOTP, and approval pages through a dedicated headless Playwright Chromium profile.

## Configure credentials

Create `~/.config/granted-auto-auth/credentials.toml` from `examples/granted-auto-auth.credentials.toml`.

```fish
chmod 700 ~/.config/granted-auto-auth
chmod 600 ~/.config/granted-auto-auth/credentials.toml
```

`totp_secret` is the Base32 `secret=` value from the `otpauth://totp/...` URI, not the rotating six-digit code. Local credential and install-state files share the repository directory but are ignored by Git. Browser state, URLs, tokens, and screenshots are never tracked.

## Install

```fish
granted-auto-browser install
granted-auto-browser doctor
```

`install` performs the network-dependent setup once: it verifies the locked PEP 723 dependencies, downloads the matching Playwright Chromium revision, records the previous Granted `CustomSSOBrowserPath`, and changes only that setting. Authentication later runs with frozen, offline dependencies.

The install state is `~/.config/granted-auto-auth/install.toml`. The dedicated browser profile is `~/.local/share/granted-auto-auth/browser/`.

When installation health passes, the Fish or Bash wrapper masks Granted's SSH/CI headless indicators for that call and runs every `assumego` invocation inside one 180-second deadline. Containers retain Granted's device-flow fallback.

## Use

```fish
assume adev
```

A valid cached token skips browser automation. An expired login starts the headless sidecar. CAPTCHA, WebAuthn, push approval, device compliance, recovery, password changes, and unknown pages fail closed.

## Disable

```fish
granted-auto-browser uninstall
```

`uninstall` restores the previous Granted browser setting. Downloaded Chromium and the dedicated browser profile are preserved for recovery or later reuse.
