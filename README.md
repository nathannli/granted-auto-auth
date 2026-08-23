# granted-auto-auth

Shell-neutral browser automation for Granted AWS IAM Identity Center reauthentication.

## Requirements

- [Granted](https://github.com/fwdcloudsec/granted) v0.39.x

See `docs/granted-auto-auth.md` for configuration, installation, and usage.

## Agent skill workflow

An agent skill can check readiness with `granted-auto-browser enabled`, then run a profile-scoped command without exporting credentials:

```bash
assume <profile> --use-authorization-code --exec -- aws sts get-caller-identity
```

A valid Granted cache returns immediately; an expired session invokes this project's headless browser sidecar. The skill should report only the AWS account and assumed-role ARN, keep credentials and authorization URLs out of logs, and stop for human action on device-code fallback or `unsupported_challenge`.
